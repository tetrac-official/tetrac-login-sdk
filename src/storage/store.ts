// The AuthStore port (v0.5.0) — the SDK's real storage extension point.
//
// WHY THIS EXISTS (see PRD/ADR-001-storage-seam.md):
// `StorageAdapter` is named for what it IS (a key-value store) rather than for what
// it is FOR (authentication state). That inverts the dependency: every backend must
// EMULATE REDIS instead of doing what it is good at, and the SDK then has to document
// at length how to emulate Redis correctly.
//
// The clearest proof is rate limiting. `StorageAdapter.incr(key)` is a PRIMITIVE, not
// a DECISION: it hands the backend a mechanism and denies it the intent. A rate-limit
// counter is "many writes to one row", which on an OCC engine (Convex) is the
// documented anti-pattern — writes conflict and eventually THROW under exactly the
// burst traffic a rate limiter exists to survive. The correct fix there is a SHARDED
// counter, which is trivial for a backend asked `hitRateLimit(...)` and IMPOSSIBLE for
// one asked `INCR`. The KV port forbids the only correct implementation.
//
// So: `AuthStore` is the domain port. Real databases (Postgres, Mongo, DynamoDB,
// Convex, Durable Objects) implement it directly and transactionally. Redis-family KV
// stores keep their `StorageAdapter` and are wrapped by `KvAuthStore` below — nothing
// existing breaks.
import type { StorageAdapter } from "./adapter.js";
import type { UserData } from "../core/types.js";
import { DEFAULT_CONFIG, type KeyPrefixes } from "../core/config.js";
import { appScoped } from "../server/keys.js";

/** The value bound to a session token: its owner, plus an optional UA fingerprint. */
export interface SessionValue {
  publicKey: string;
  /** Set only when the session was issued with config.bindSessionToUserAgent on. */
  fingerprint?: string;
}

/** The decision returned by {@link AuthStore.hitRateLimit}. */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

/**
 * A rate-limit bucket, STRUCTURED rather than a concatenated string. This is the last
 * place the SDK used to build an opaque key, and passing the parts as fields is what
 * lets a backend index the bucket — and shard it, which is the whole point (see above).
 *
 * `appId` is absent for the client-IP bucket, which is deliberately GLOBAL across
 * endpoints and apps (one abusive IP is throttled everywhere at once).
 */
export interface RateLimitBucket {
  /** The endpoint the limit applies to, e.g. "login". The literal "ip" for the IP bucket. */
  endpoint: string;
  /** The tenant, when the bucket is app-scoped. Omitted for the global IP bucket. */
  appId?: string;
  /** The thing being limited: an email, a public key, or an IP. Attacker-influenced. */
  identifier: string;
}

/**
 * Normalize an email for INDEX purposes. Every AuthStore implementation MUST route
 * both the write (`putUser`'s email index) and the read (`getPublicKeyByEmail`) through
 * this, so that "A@B.com" and "a@b.com" are the same account on every backend.
 *
 * It is exported (rather than left to each backend) precisely so that no backend can
 * accidentally delegate case-insensitivity to its collation — which on MySQL would
 * ALSO case-fold the appId and the base58 public key, silently merging distinct tenants
 * and distinct accounts. Case-insensitivity is a property of the EMAIL, not of the
 * keyspace.
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * The storage contract for the SDK's server layer.
 *
 * Three invariants bind EVERY implementation, and each one is a required conformance
 * case (`storage/conformance.ts`). They are the ones that cannot be designed away:
 *
 *  1. EXPIRY IS ENFORCED ON READ. `getSession` and `takeChallenge` MUST return null for
 *     an expired value even if no sweeper has ever run. A TTL index, a cron, or
 *     `sweepExpired` is SPACE RECLAMATION ONLY and is never the expiry authority.
 *     (Mongo's TTL sweep is ~60s late; DynamoDB's is "within a few days"; Firestore's
 *     docs say expired documents keep appearing in queries. Relying on them means
 *     accepting expired session tokens.)
 *
 *  2. `takeChallenge` IS ATOMIC. It is the sole mechanism closing the challenge-replay
 *     race: N concurrent callers, at most ONE observes the value.
 *
 *  3. ERRORS FAIL CLOSED. Propagate them. `null` means "the backend answered, and it is
 *     absent" — NEVER "the backend did not answer". An implementation that catches a
 *     failure and returns `{allowed: true}` from `hitRateLimit`, or `null` from `get*`,
 *     has silently switched off a security control under exactly the load that broke it.
 */
export interface AuthStore {
  // --- users -------------------------------------------------------------------
  getUser(appId: string, publicKey: string): Promise<UserData | null>;
  /** Upsert the record AND maintain the email index. Both, or neither — one transaction
   *  where the backend supports it. Concurrent putUser for the same email under two
   *  different appIds must not lose either write. */
  putUser(user: UserData): Promise<void>;
  /** Resolve an email to its publicKey for ONE app. Matched via {@link normalizeEmail}. */
  getPublicKeyByEmail(appId: string, email: string): Promise<string | null>;

  // --- challenges (single-use, TTL-bound) ---------------------------------------
  putChallenge(appId: string, publicKey: string, challenge: string, ttlSeconds: number): Promise<void>;
  /** ATOMIC get-and-delete. Returns the stored challenge and removes it; null if absent
   *  OR expired. The CALLER does the constant-time compare — never the backend. */
  takeChallenge(appId: string, publicKey: string): Promise<string | null>;

  // --- sessions (keyed by the token's SHA-256 digest, never the token) -----------
  putSession(appId: string, tokenHash: string, value: SessionValue, ttlSeconds: number): Promise<void>;
  /** null when absent OR expired (invariant 1). */
  getSession(appId: string, tokenHash: string): Promise<SessionValue | null>;
  deleteSession(appId: string, tokenHash: string): Promise<void>;

  // --- rate limiting -------------------------------------------------------------
  /**
   * ONE atomic call that increments the window counter and returns the DECISION.
   *
   * The backend owns the whole window: it must ensure that once a window elapses, a
   * previously-limited identifier is allowed again. (The classic way to get this wrong
   * is a counter that outlives its TTL — the identifier is then rate-limited FOREVER,
   * a self-inflicted permanent denial of service that no smoke test catches because it
   * only appears after a window elapses under sustained traffic.)
   *
   * Backends are free to implement this however they like — a single row, a sharded
   * counter, a token bucket — as long as the observable behavior holds and it never
   * fails open.
   */
  hitRateLimit(bucket: RateLimitBucket, windowSeconds: number, maxAttempts: number): Promise<RateLimitResult>;

  // --- lifecycle (OPTIONAL — callers feature-detect) ------------------------------
  /**
   * OPTIONAL. Delete expired entries; returns how many were removed. `limit` bounds one
   * batch. SPACE RECLAMATION ONLY — never the expiry authority (invariant 1). Backends
   * with native, exact expiry (Redis) omit it.
   *
   * Note for durable backends: expired rows are not just disk. Rate-limit buckets embed
   * EMAILS and IPs, so never sweeping them is a data-retention problem, not a
   * housekeeping backlog item.
   */
  sweepExpired?(limit?: number): Promise<number>;
  /** OPTIONAL. Release pooled connections / handles. Idempotent. Backends over a
   *  stateless REST client or an in-process Map omit it. */
  close?(): Promise<void>;
}

/**
 * Adapts any {@link StorageAdapter} (the Redis-shaped KV port) to an {@link AuthStore}.
 *
 * This is how Redis / Upstash / Vercel KV / Memory keep working unchanged: the SDK's
 * server layer talks only to AuthStore, and a KV backend gets wrapped here. The body is
 * the SDK's pre-v0.5.0 session/challenge/rateLimit logic, moved behind the interface —
 * so the Redis keyspace and semantics are exactly what they always were.
 */
export class KvAuthStore implements AuthStore {
  private readonly kv: StorageAdapter;
  private readonly prefixes: KeyPrefixes;

  /**
   * Present ONLY when the wrapped adapter provides them, so that feature-detection
   * (`store.close?.()`) stays truthful through the wrapper: a KvAuthStore over Redis
   * must not claim to support a sweep that Redis does not need and does not have.
   */
  readonly sweepExpired?: (limit?: number) => Promise<number>;
  readonly close?: () => Promise<void>;

  constructor(kv: StorageAdapter, prefixes: KeyPrefixes = DEFAULT_CONFIG.keyPrefixes) {
    this.kv = kv;
    this.prefixes = prefixes;
    // Assigned in the constructor body (not as field initializers) so they are wired
    // after `kv` is set, regardless of class-field emit semantics.
    if (kv.sweepExpired) this.sweepExpired = (limit?: number) => kv.sweepExpired!(limit);
    if (kv.close) this.close = () => kv.close!();
  }

  // The email index key is deliberately NOT app-scoped: one email maps to a per-app
  // publicKey under each appId FIELD of a hash, so a shared DB can answer "which apps
  // does this email use?". The per-field write is what makes two concurrent
  // registrations of the same email under different appIds safe (v0.4.0).
  private emailKey(email: string): string {
    return `${this.prefixes.email}${normalizeEmail(email)}`;
  }

  private rateLimitKey(b: RateLimitBucket): string {
    // Mirrors the historical layout: `ratelimit:{endpoint}:{appId}:{identifier}`, and
    // `ratelimit:ip:{identifier}` for the app-agnostic IP bucket.
    const scope = b.appId === undefined ? b.endpoint : `${b.endpoint}:${b.appId}`;
    return `${this.prefixes.rateLimit}${scope}:${b.identifier}`;
  }

  async getUser(appId: string, publicKey: string): Promise<UserData | null> {
    const raw = await this.kv.get(appScoped(this.prefixes.pubKey, appId, publicKey));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as UserData;
    } catch {
      return null; // malformed/non-JSON value — fail safe instead of throwing
    }
  }

  async putUser(user: UserData): Promise<void> {
    await this.kv.set(appScoped(this.prefixes.pubKey, user.appId, user.publicKey), JSON.stringify(user));
    if (user.email) {
      await this.kv.hset(this.emailKey(user.email), user.appId, user.publicKey);
    }
  }

  async getPublicKeyByEmail(appId: string, email: string): Promise<string | null> {
    return this.kv.hget(this.emailKey(email), appId);
  }

  async putChallenge(appId: string, publicKey: string, challenge: string, ttlSeconds: number): Promise<void> {
    await this.kv.set(appScoped(this.prefixes.challenge, appId, publicKey), challenge, {
      exSeconds: ttlSeconds,
    });
  }

  async takeChallenge(appId: string, publicKey: string): Promise<string | null> {
    // One GETDEL: two concurrent consumes cannot both read the value before either
    // deletes it — only one sees it. This is the entire challenge-replay defense.
    return this.kv.getdel(appScoped(this.prefixes.challenge, appId, publicKey));
  }

  async putSession(appId: string, tokenHash: string, value: SessionValue, ttlSeconds: number): Promise<void> {
    await this.kv.set(appScoped(this.prefixes.session, appId, tokenHash), encodeSession(value), {
      exSeconds: ttlSeconds,
    });
  }

  async getSession(appId: string, tokenHash: string): Promise<SessionValue | null> {
    const raw = await this.kv.get(appScoped(this.prefixes.session, appId, tokenHash));
    return raw == null ? null : decodeSession(raw);
  }

  async deleteSession(appId: string, tokenHash: string): Promise<void> {
    await this.kv.del(appScoped(this.prefixes.session, appId, tokenHash));
  }

  async hitRateLimit(
    bucket: RateLimitBucket,
    windowSeconds: number,
    maxAttempts: number,
  ): Promise<RateLimitResult> {
    const key = this.rateLimitKey(bucket);
    const count = await this.kv.incr(key);
    if (count === 1) {
      // First hit in a window: stamp the TTL. (Redis INCR on an expired key returns 1
      // and drops the stale TTL, which is what makes this correct — and is exactly the
      // invariant a naive SQL upsert gets wrong, producing a permanent lockout.)
      await this.kv.expire(key, windowSeconds);
    } else if (count > maxAttempts) {
      // Self-heal: a crash between a prior incr and its expire would leave the counter
      // wedged over the limit with NO TTL, blocking this identifier forever. Re-applying
      // expire is cheap and idempotent and guarantees the counter can drain.
      await this.kv.expire(key, windowSeconds);
    }
    return {
      allowed: count <= maxAttempts,
      remaining: Math.max(0, maxAttempts - count),
    };
  }
}

// The session value is normally just the owner's publicKey; with UA-binding it becomes
// "publicKey|fingerprint". Kept as a string ONLY because that is the historical Redis
// encoding and changing it would invalidate live sessions for no benefit. Wallet public
// keys (base58 / hex) never contain "|", so the split is unambiguous.
//
// NOTE: a native AuthStore backend should NOT copy this — it should store `publicKey`
// and `fingerprint` as two typed fields. The encoding is an artifact of the KV port.
function encodeSession(v: SessionValue): string {
  return v.fingerprint ? `${v.publicKey}|${v.fingerprint}` : v.publicKey;
}

function decodeSession(raw: string): SessionValue {
  const i = raw.indexOf("|");
  return i === -1 ? { publicKey: raw } : { publicKey: raw.slice(0, i), fingerprint: raw.slice(i + 1) };
}
