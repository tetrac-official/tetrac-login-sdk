// Framework-agnostic auth route handlers built on the Web Request/Response API.
// Next.js App Router consumes these directly via src/next.
import type { StorageAdapter } from "../storage/adapter.js";
import {
  KvAuthStore,
  normalizeEmail,
  EmailTakenError,
  type AuthStore,
  type RateLimitBucket,
} from "../storage/store.js";
import {
  resolveConfig,
  APP_ID_HEADER,
  AUTH_TOKEN_HEADER,
  PUBLIC_KEY_HEADER,
  PBKDF2_ITERATIONS,
  type AuthConfig,
  type DeepPartial,
} from "../core/config.js";
import {
  WALLET_SLOTS,
  type AuthResult,
  type EncryptedWallet,
  type OffchainEnvelope,
  type UserData,
} from "../core/types.js";
import { PublicKey } from "@solana/web3.js";
import { json, error, clientIp, readJson } from "./http.js";
import { hashUserAgent, generateChallenge } from "../core/crypto.js";
import { checkRateLimit } from "./rateLimit.js";
import { issueChallenge, consumeChallenge } from "./challenge.js";
import { verifySolanaSignature, verifyAuthSignature } from "./signature.js";
import {
  persistUser,
  getUserByPublicKey,
  resolvePublicKeyByEmail,
  issueSession,
  verifySession,
  revokeSession,
} from "./session.js";

/**
 * Supply EITHER `store` (an AuthStore — the domain port, and what a real database should
 * implement) OR `storage` (a Redis-shaped StorageAdapter, which is wrapped automatically).
 *
 * `storage` remains fully supported: every existing deployment keeps working untouched.
 */
export interface AuthHandlerOptions {
  /** A Redis-family KV backend. Wrapped in a KvAuthStore for you. */
  storage?: StorageAdapter;
  /** A native domain backend. Takes precedence over `storage` when both are given. */
  store?: AuthStore;
  config?: DeepPartial<AuthConfig>;
  /**
   * Called with any boot-time configuration finding. Defaults to `console.warn`, matching
   * `createSqlAuthStore`. Pass a no-op to silence, or route them into your logger.
   */
  onWarning?: (issue: ConfigWarning) => void;
  /**
   * OPTIONAL gate on ACCOUNT CREATION. Called on the creation branch of `/register` and
   * `/connect-wallet` — never on a returning user's sign-in — before the deployment
   * ceiling. Return `false` (or throw) to refuse creation with `403`.
   *
   * This is the escape valve for the creation-ceiling denial-of-service (audit 2026-08-08
   * F-4): the deployment-wide `create` bucket is both the anti-abuse control AND a service
   * every real signup depends on, so an attacker can hold it exhausted at the limit rate
   * and close registration for everyone. A per-IP fallback exists when `trustProxyHeaders`
   * is on, but a deployment that cannot supply a trustworthy IP has no per-source control
   * at all. Wire a proof-of-work check, CAPTCHA, invite code, or verified-email gate here —
   * the same gate `SECURITY.md` recommends when email must mean identity.
   */
  beforeCreateAccount?: (req: Request) => boolean | Promise<boolean>;
}

/** A boot-time configuration finding. Mirrors the SQL layer's `PreflightIssue`. */
export interface ConfigWarning {
  /** Stable machine-readable code, e.g. `unrestricted_app_id`. */
  code: string;
  message: string;
}

// Warn ONCE per process per (code, appId).
//
// These are boot findings, but `createAuthHandlers` is not guaranteed to run once: a
// serverless runtime re-evaluates the module per cold start, and a multi-tenant host may
// build one handler set per app. A warning repeated on every construction is a warning
// people filter out, which is the same as not emitting it. Keying on appId as well as code
// means a host serving several apps still hears about each one.
const warned = new Set<string>();

function warnOnce(appId: string, issue: ConfigWarning, sink?: (issue: ConfigWarning) => void): void {
  const key = `${issue.code}:${appId}`;
  if (warned.has(key)) return;
  warned.add(key);
  if (sink) sink(issue);
  // eslint-disable-next-line no-console
  else console.warn(`[tetrac] ${issue.code}: ${issue.message}`);
}

/**
 * Boot-time configuration findings. These WARN rather than throw: both conditions are
 * legitimate in development, and a hard failure would break every single-app deployment
 * that correctly relies on the `config.appId` fallback and never sends one.
 *
 * `appId` is not a label. It is (a) the storage namespace prefixing every key and (b)
 * app-key DERIVATION INPUT on both paths — the PBKDF2 salt is `SHA-256(appId : email)`
 * and the wallet app-key message embeds `App: {appId}`. Those two facts together are why
 * an unchecked appId is a data-loss hazard rather than a tidiness one.
 */
function checkConfig(config: AuthConfig, sink?: (issue: ConfigWarning) => void): void {
  if (!config.allowedAppIds) {
    warnOnce(
      config.appId,
      {
        code: "unrestricted_app_id",
        message:
          `config.allowedAppIds is unset — every route accepts ANY well-formed appId from the ` +
          `request body, the '${APP_ID_HEADER}' header, or the ?appId query param, and silently ` +
          `creates that namespace. A client sending 'myapp' against a deployment configured as ` +
          `'myapp.example' therefore registers successfully into a SEPARATE tenant under a ` +
          `DIFFERENT app key, and the wallets it encrypts there can never be decrypted by the ` +
          `real one. Set allowedAppIds to the exact ids this deployment serves ` +
          `(e.g. ['${config.appId}']).`,
      },
      sink,
    );
  }
  if (config.appId === "ttc") {
    warnOnce(
      config.appId,
      {
        code: "default_app_id",
        message:
          `config.appId is the default 'ttc' — it provides NO cross-app key isolation, since ` +
          `any other deployment on the default derives the same app keys from the same email. ` +
          `Set a unique, stable id per deployment (your domain works well). Set it ONCE: it is ` +
          `app-key derivation input, so changing it later re-derives every key and existing ` +
          `encrypted wallets stop decrypting.`,
      },
      sink,
    );
  }
  if (!config.trustProxyHeaders) {
    warnOnce(
      config.appId,
      {
        code: "no_requester_identity",
        message:
          `config.trustProxyHeaders is false, so there is no trustworthy client IP and the ` +
          `per-IP rate limit is SKIPPED entirely. Two consequences: anti-abuse buckets fall ` +
          `back to keying on the caller-supplied email/publicKey, so an attacker who names an ` +
          `account can spend that account's own /challenge budget and hold it out of login; ` +
          `and because each probed identifier gets its own counter, a horizontal sweep of N ` +
          `addresses is N unthrottled requests. Behind a known proxy (Vercel, Cloudflare, an ` +
          `ingress you control) set trustProxyHeaders: true and trustedProxyHops to the ` +
          `number of hops you operate. Do NOT set it when the app is directly reachable — ` +
          `x-forwarded-for is caller-supplied there, and trusting it is worse than this.`,
      },
      sink,
    );
  }
}

export interface AuthHandlers {
  config: AuthConfig;
  challenge(req: Request): Promise<Response>;
  register(req: Request): Promise<Response>;
  login(req: Request): Promise<Response>;
  loginWallet(req: Request): Promise<Response>;
  connectWallet(req: Request): Promise<Response>;
  logout(req: Request): Promise<Response>;
  userData(req: Request): Promise<Response>;
  searchWallet(req: Request): Promise<Response>;
  importWallet(req: Request): Promise<Response>;
}

// --- request input validators (v0.2.1 Change 4) ---
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX64_RE = /^[0-9a-f]{64}$/i;
// appId is now attacker-influenced (request body / header), and it is concatenated
// into Redis keys, so it must be validated BEFORE it ever reaches a key (v0.4.0).
// The charset forbids ':' (the key-namespace separator) and whitespace, and bounds
// the length, so a crafted appId can neither escape its namespace nor bloat keys.
const APP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// 🚨 Every validator here TYPE-CHECKS FIRST.
//
// The body is JSON.parse output, so a field the TypeScript signature calls `string` can be
// an array, a number, or an object at runtime. `EMAIL_RE.test(["a@b.co"])` is TRUE — RegExp
// coerces its argument — and `["a@b.co"].length` is 1, so an array passed BOTH the format
// check and the 320 bound. It then reached normalizeEmail(), where `.toLowerCase()` does not
// exist on an array: an unauthenticated request turned into a framework 500.
function validateEmail(email: unknown): string | null {
  if (typeof email !== "string") return "Invalid email format";
  if (email.length > 320 || !EMAIL_RE.test(email)) return "Invalid email format";
  return null;
}

function validateAppId(appId: unknown, config: AuthConfig): string | null {
  if (typeof appId !== "string" || !appId || !APP_ID_RE.test(appId)) return "Invalid appId format";
  // Optional production allowlist: reject any appId the deployment didn't declare,
  // so an attacker can't mint arbitrary namespaces or probe tenants by guessing ids.
  if (config.allowedAppIds && !config.allowedAppIds.includes(appId)) return "Unknown appId";
  return null;
}

function validatePublicKey(key: unknown): string | null {
  // The account identity is a Solana ed25519 public key (generated client-side for
  // email/biometric, or the connected wallet for web3). Require base58 that decodes to
  // exactly 32 bytes in CANONICAL form: PublicKey throws on invalid base58 / wrong
  // length, the round-trip rejects short inputs PublicKey would left-pad, and EVM
  // `0x…` addresses fail because `0` isn't in the base58 alphabet.
  if (typeof key !== "string" || !key) return "Invalid publicKey format";
  try {
    const pk = new PublicKey(key);
    if (pk.toBytes().length !== 32 || pk.toBase58() !== key) return "Invalid publicKey format";
  } catch {
    return "Invalid publicKey format";
  }
  return null;
}

function validateAuthPublicKey(key: unknown): string | null {
  if (typeof key !== "string" || !HEX64_RE.test(key)) return "Invalid authPublicKey format"; // ed25519 public key, 32 bytes hex
  return null;
}

// PBKDF2 iteration bounds the server pins per-user. The client picks securityLevel
// (1/2/3 -> 100k/600k/1M), but the server must not trust the count blindly (audit F3):
// a malicious/buggy client could pin `1` and kneecap that account's brute-force
// resistance. Floor = the documented level-1 (legacy) minimum; ceiling = level-3.
const PBKDF2_MIN = 100_000;
const PBKDF2_MAX = 1_000_000;
/** The off-chain envelope pinned on a hardware account. Derivation input — validate it. */
function validEnvelope(v: unknown): v is OffchainEnvelope {
  return v === "legacy" || v === "v0";
}

function validIterations(n: unknown): boolean {
  return typeof n === "number" && Number.isInteger(n) && n >= PBKDF2_MIN && n <= PBKDF2_MAX;
}

// authMethod is a PERSISTED field, so it gets the same allowlist discipline as every other
// one (audit 2026-08-08 F-3). It was the lone field written straight from the body —
// `body.authMethod ?? "email"` — so an anonymous caller could persist any type or an
// unbounded string in a field that never expires and round-trips to every client, and that
// the server's own `authMethod !== "wallet"` guard then tests. Closed union, absence
// defaults to "email" (unchanged).
const AUTH_METHODS: readonly UserData["authMethod"][] = ["email", "wallet", "biometric"];
function validAuthMethod(v: unknown): v is UserData["authMethod"] {
  return typeof v === "string" && (AUTH_METHODS as readonly string[]).includes(v);
}

export function createAuthHandlers(opts: AuthHandlerOptions): AuthHandlers {
  const config = resolveConfig(opts.config);
  checkConfig(config, opts.onWarning);
  // A native AuthStore wins; otherwise wrap the KV adapter. One of the two is required.
  const store: AuthStore =
    opts.store ??
    (opts.storage
      ? new KvAuthStore(opts.storage, config.keyPrefixes)
      : (() => {
          throw new Error(
            "[tetrac] createAuthHandlers requires either `store` (AuthStore) or `storage` (StorageAdapter).",
          );
        })());

  // Apply rate limiting; returns a 429 Response or null.
  //
  // The IP leg runs only when we have a TRUSTWORTHY IP — which means both that the
  // deployment trusts its proxy AND that this particular request actually carried the
  // header. Either condition failing yields null, never a shared sentinel, because a
  // shared sentinel is a global lockout: every caller lands in one bucket and normal
  // traffic locks out the whole deployment at 10/60s.
  //
  // Buckets are ENDPOINT-SCOPED so one endpoint's limit can never bleed into and lock a
  // victim out of a DIFFERENT endpoint they need — e.g. failed logins must not exhaust the
  // bucket the victim's /challenge uses.
  //
  // The IP bucket carries no appId on purpose: it is global across endpoints and apps,
  // so one abusive IP is throttled everywhere at once.
  async function rateLimited(req: Request, bucket?: RateLimitBucket): Promise<Response | null> {
    // Gate on the IP only when clientIp() actually produced one. Keying on a "no IP"
    // sentinel would put every caller in ONE bucket — one abuser, or merely normal traffic,
    // then locks out the whole deployment at 10/60s. That happens whenever
    // trustProxyHeaders is true but a request arrives without the proxy headers: direct
    // origin access, a health check, a bypassed CDN, local dev.
    const ip = requesterIp(req);
    if (ip) {
      // The IP bucket has its OWN limit (config.ipRateLimit), not the per-endpoint
      // rateLimit — it aggregates ALL traffic from one address, so it must be sized for
      // shared egress IPs (NAT/CGNAT/VPN), not per-identifier volume (audit F-7).
      const r = await checkRateLimit(store, { endpoint: "ip", identifier: ip }, config.ipRateLimit);
      if (!r.allowed) return error("Rate limit exceeded", 429);
    }
    if (bucket) {
      const id = await checkRateLimit(store, bucket, config.rateLimit);
      if (!id.allowed) return error("Rate limit exceeded", 429);
    }
    return null;
  }

  /** The requester's IP, or null when this deployment cannot trust one. */
  function requesterIp(req: Request): string | null {
    return config.trustProxyHeaders ? clientIp(req, true, config.trustedProxyHops) : null;
  }

  /**
   * Bucket key for a caller-supplied identifier.
   *
   * An email MUST be normalized the same way the lookup normalizes it. `getPublicKeyByEmail`
   * applies normalizeEmail, so `Victim@x.com`, `victim@x.com`, and ` victim@x.com ` are ONE
   * account — but keying the bucket on the raw string gave each spelling its own counter,
   * dividing the per-account throttle by however many case permutations an attacker cares
   * to type. A public key is base58 and case-SENSITIVE, so it is passed through untouched.
   */
  function bucketId(value: string): string {
    return value.includes("@") ? normalizeEmail(value) : value;
  }

  // The ceiling on NEW ACCOUNTS. Keyed on a trustworthy IP when there is one, and on a
  // single deployment-wide "global" identifier only as the fallback.
  //
  // Every OTHER bucket is keyed on an email or a public key lifted from the request body,
  // so an attacker who generates a fresh keypair per request gets a fresh counter and the
  // limit never fires — which is how an anonymous client creates unbounded, permanent,
  // un-swept records. Creation must therefore key on something the caller cannot rotate.
  //
  // A single GLOBAL counter has that property but pays for it symmetrically: the defender
  // has no key to rotate either, so an attacker holds the one bucket exhausted at the limit
  // rate and closes registration for the whole deployment (audit 2026-08-08 F-4). So when a
  // trustworthy IP exists we charge THAT instead — one abuser is bounded to their own IP,
  // legitimate users on other IPs are untouched — mirroring /challenge's requester-vs-target
  // reasoning. With no IP the global bucket is the only unrotatable key left; `beforeCreate`
  // (below) is what protects that case, and it runs regardless of IP.
  //
  // CALL THIS ONLY WHERE A RECORD IS ACTUALLY CREATED. The client's "auto" mode registers
  // first and falls back to login on 409, so returning users hit /register on every normal
  // sign-in; charging them would turn a 2/min creation ceiling into a 2/min login ceiling.
  async function accountCreationLimited(req: Request): Promise<Response | null> {
    // Integrator gate first: the only creation control that works with no trustworthy IP.
    // A throw is treated as "refused", so a failing CAPTCHA/PoW backend fails closed.
    if (opts.beforeCreateAccount) {
      let ok = false;
      try {
        ok = await opts.beforeCreateAccount(req);
      } catch {
        ok = false;
      }
      if (!ok) return error("Account creation refused", 403);
    }
    const ip = requesterIp(req);
    const bucket: RateLimitBucket = ip
      ? { endpoint: "create", identifier: ip }
      : { endpoint: "create", identifier: "global" };
    const r = await checkRateLimit(store, bucket, config.accountCreationRateLimit);
    return r.allowed ? null : error("Too many new accounts right now — try again shortly", 429);
  }

  // Every wallet signature is verified against config.origin — SERVER config, never the
  // request. Echoing a client-supplied origin back into the message would reinstate
  // exactly the relay attack the binding exists to prevent. resolveConfig guarantees the
  // value is present (it throws otherwise), so there is no unbound-verification path to
  // fall back to.

  // Optional coarse session→User-Agent binding (config.bindSessionToUserAgent,
  // default off). At ISSUE time we fingerprint only when the flag is on; at VERIFY
  // time we always compute the request fingerprint and let verifySession enforce it
  // iff the session was bound — so flipping the flag off never un-binds live sessions.
  function issueFingerprint(req: Request): string | undefined {
    return config.bindSessionToUserAgent ? hashUserAgent(req.headers.get("user-agent")) : undefined;
  }
  function reqFingerprint(req: Request): string | undefined {
    return hashUserAgent(req.headers.get("user-agent"));
  }

  // Resolve the request's appId on authenticated routes from APP_ID_HEADER, falling
  // back to config.appId for single-app deployments. Returns null when the supplied
  // value is malformed (e.g. contains the ':' key separator) so the caller can fail
  // closed (401) rather than build a key from attacker-controlled input (v0.4.0).
  function headerAppId(req: Request): string | null {
    const appId = req.headers.get(APP_ID_HEADER) ?? config.appId;
    return validateAppId(appId, config) ? null : appId;
  }

  // Client-safe copy of a user record. `authTokenHash` is the session identifier (not a
  // credential — it is a SHA-256 digest), but the client has no use for it, so it never
  // leaves the server. `authToken` is the pre-v0.5.0 raw-token field: still stripped,
  // because a record written by an older version may carry one until its next write.
  // authPublicKey IS public key material, so it stays.
  function publicUser(user: UserData): UserData {
    const { authToken: _authToken, authTokenHash: _authTokenHash, ...safe } = user;
    return safe as UserData;
  }

  // The raw token is passed in explicitly rather than read back off `user`. Before
  // v0.5.0 issueSession mutated `user.authToken` and this read it from there — a
  // side-channel that only worked because the raw token was persisted. It no longer is.
  function asResult(user: UserData, token: string): AuthResult {
    return { publicKey: user.publicKey, authToken: token, user: publicUser(user) };
  }

  // Validate a client-supplied wallets[] payload. Returns an error Response (400) or null
  // when the array is acceptable.
  //
  // A user record holds AT MOST ONE wallet per (chain, role) — four slots, no more (see
  // WALLET_SLOTS). That bound is what keeps the encrypted blob a fixed-size object instead
  // of an append-only list, and it is enforced here rather than by a numeric cap: a request
  // carrying two entries for the same slot is malformed, not merely large.
  function readWallets(wallets: unknown): { error: Response } | { wallets: EncryptedWallet[] } {
    if (!Array.isArray(wallets)) return { error: error("wallets must be an array") };
    if (wallets.length > WALLET_SLOTS.length) return { error: error("too many wallets") };
    const seen = new Set<string>();
    const clean: EncryptedWallet[] = [];
    for (const w of wallets) {
      if (!w || typeof w !== "object") return { error: error("invalid wallet entry") };
      const e = w as Record<string, unknown>;
      if (typeof e.publicKey !== "string" || typeof e.encryptedSecret !== "string") {
        return { error: error("invalid wallet entry") };
      }
      if (e.publicKey.length > 128) return { error: error("wallet publicKey too long") };
      if (e.role !== "funds" && e.role !== "signing") return { error: error("invalid wallet entry") };
      if (e.chain !== "solana" && e.chain !== "evm") return { error: error("invalid wallet entry") };
      if (e.encryptedSecret.length > 8192) return { error: error("encryptedSecret too large") };
      const slot = `${e.chain}:${e.role}`;
      if (seen.has(slot)) return { error: error("duplicate wallet slot") };
      seen.add(slot);
      // REBUILD from an allowlist — never persist the caller's object.
      //
      // Validating the known fields and then storing what arrived is not the same thing.
      // Unknown properties were carried through verbatim into JSON.stringify(user), so a
      // single anonymous /register carrying `{chain, role, publicKey, encryptedSecret,
      // junk: "x".repeat(5_000_000)}` persisted 5 MB — every bound above satisfied. The
      // four fields below are the entire wire contract; anything else is dropped here,
      // which makes the stored size a function of the bounds rather than of the caller.
      clean.push({
        chain: e.chain,
        role: e.role,
        publicKey: e.publicKey,
        encryptedSecret: e.encryptedSecret,
      });
    }
    return { wallets: clean };
  }

  return {
    config,

    async challenge(req) {
      const body = await readJson<{ appId?: string; publicKey?: string; email?: string }>(req);
      const appId = body?.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      if (body?.publicKey) {
        const e = validatePublicKey(body.publicKey);
        if (e) return error(e);
      }
      if (body?.email) {
        const e = validateEmail(body.email);
        if (e) return error(e);
      }
      // Charge the IP leg FIRST (a no-op without a trustworthy IP). When we have one it
      // bounds this request — reads and all — before any storage work, so the resolution
      // below cannot be spun as a cheap-read amplifier.
      const ipLimited = await rateLimited(req);
      if (ipLimited) return ipLimited;

      // Resolve the identity key up front. Wallet flow passes publicKey; email/biometric
      // flow passes the account email (or internal biometric id), which resolves to the
      // identity publicKey. This is a READ — it issues and stores nothing — and it is what
      // lets the anti-abuse bucket tell a real ACCOUNT (bound per-account, not rotatable)
      // from an UNKNOWN key an attacker rotates a fresh keypair into on every request.
      let publicKey = body?.publicKey ?? null;
      if (!publicKey && body?.email) {
        publicKey = await resolvePublicKeyByEmail(store, appId, body.email);
      }
      // Neither identifier supplied — a malformed request, not a probe. Still a 400.
      if (!publicKey && !body?.email) return error("publicKey or email required");
      const user = publicKey ? await getUserByPublicKey(store, appId, publicKey) : null;

      // Rate-limit BEFORE issuing, so an UNKNOWN-key/email probe is charged too. Issuing a
      // challenge grants no capability, so charging a named TARGET is backwards — the
      // attacker names the victim and the victim's own /challenge then 429s, a complete
      // auth denial held open at the limit rate. So:
      //
      //   trustworthy IP     -> already charged above (the requester); touch no target.
      //   no IP, KNOWN key   -> the per-account target bucket. It is a real account, not
      //                         rotatable, so this bounds abuse of THAT account's issuance
      //                         without one caller being able to throttle another.
      //   no IP, UNKNOWN key -> a GLOBAL bucket, NOT the caller's key (audit 2026-08-08
      //                         F-5). A fresh keypair per request must not buy a fresh
      //                         counter, or an attacker writes an unbounded set of stored
      //                         challenges (and an unbounded set of per-identifier
      //                         rate-limit rows). An unknown key must still get a STORED
      //                         challenge — registration proves possession of a key with no
      //                         record yet — so the write is BOUNDED, not refused. Known-key
      //                         logins never touch this bucket, so they are unaffected; only
      //                         new-account challenge fetches share it, and only in the
      //                         trustProxyHeaders-off config already flagged as degraded
      //                         (the no_requester_identity boot warning).
      if (!requesterIp(req)) {
        const targetBucket: RateLimitBucket =
          user && publicKey
            ? { endpoint: "challenge", appId, identifier: bucketId(publicKey) }
            : { endpoint: "challenge-unknown", identifier: "global" };
        const limited = await rateLimited(req, targetBucket);
        if (limited) return limited;
      }

      if (!publicKey) {
        // UNKNOWN EMAIL — answer in the shape a real account would, and store nothing.
        //
        // This branch used to return 400 while a registered address returned 200, which is
        // a clean account-existence oracle for anyone who can POST. Since the per-target
        // bucket gives each probed address its own counter, sweeping N addresses cost N
        // unthrottled requests: the throttle could see depth on one identifier but never
        // breadth across many.
        //
        // The dummy is safe to hand out precisely because a challenge is not a secret: it
        // is server-issued, public to whoever asked, and worthless without a signature from
        // an authPublicKey no record holds. Never persisting it means /login fails at
        // signature verification exactly as a wrong passkey does, so the two are
        // indistinguishable there too.
        //
        // `pbkdf2Iterations` must carry the deployment's OWN default rather than being
        // omitted: an absent field would re-open the oracle one key over, and the default
        // is the modal value across real accounts anyway. `offchainEnvelope` is genuinely
        // absent for every email account, so omitting it here matches.
        //
        // NOT constant-time: the real path performs storage work this one skips, so a
        // determined attacker can still separate them by latency. This closes the trivial
        // read, not the side channel.
        return json({
          challenge: generateChallenge(),
          pbkdf2Iterations: PBKDF2_ITERATIONS[config.securityLevel],
        });
      }

      const challenge = await issueChallenge(store, appId, publicKey, config);
      // Accounts also need their PINNED derivation parameters back before they can sign:
      // the PBKDF2 iteration count (email) and the off-chain envelope (hardware wallet).
      // Both are app-key derivation input and neither is secret. Re-deriving with a
      // different value silently yields a different key and undecryptable wallets. `user`
      // was resolved above (one read, reused here).
      // ALWAYS emit a number — never omit the field.
      //
      // An omitted key is itself the oracle: a record with no pinned count answered
      // `{challenge}` while the unknown-email dummy answers `{challenge, pbkdf2Iterations}`,
      // so closing the status-code tell would just have moved it one key over. The server
      // is now the single authority for the count, which also removes the client's old
      // guess-100k-when-absent fallback — a guess only ever right by luck.
      //
      // Registration pins a count for every email account, so this default is reached only
      // by a record written without one; the deployment's configured level is the closest
      // thing to a correct answer for it. Wallet and biometric accounts carry no count and
      // ignore the field entirely — they derive from a signature or a PRF, not PBKDF2.
      return json({
        challenge,
        pbkdf2Iterations: user?.pbkdf2Iterations ?? PBKDF2_ITERATIONS[config.securityLevel],
        offchainEnvelope: user?.offchainEnvelope,
      });
    },

    async register(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        email?: string;
        authPublicKey?: string;
        authMethod?: UserData["authMethod"];
        wallets?: EncryptedWallet[];
        signature?: string;
        challenge?: string;
        pbkdf2Iterations?: number;
        offchainEnvelope?: OffchainEnvelope;
      }>(req);
      if (!body?.publicKey) return error("publicKey required");
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);
      if (body.email) {
        const emailErr = validateEmail(body.email);
        if (emailErr) return error(emailErr);
      }
      if (body.authPublicKey) {
        const apErr = validateAuthPublicKey(body.authPublicKey);
        if (apErr) return error(apErr);
      }
      let wallets: EncryptedWallet[] = [];
      if (body.wallets !== undefined) {
        const r = readWallets(body.wallets);
        if ("error" in r) return r.error;
        wallets = r.wallets;
      }
      // Reject a client-supplied PBKDF2 count outside the allowed band (audit F3).
      // Absent is fine — legacy/wallet accounts don't pin one.
      if (body.pbkdf2Iterations != null && !validIterations(body.pbkdf2Iterations)) {
        return error("Invalid pbkdf2Iterations", 400);
      }
      if (body.offchainEnvelope != null && !validEnvelope(body.offchainEnvelope)) {
        return error("Invalid offchainEnvelope", 400);
      }
      if (body.authMethod != null && !validAuthMethod(body.authMethod)) {
        return error("Invalid authMethod", 400);
      }

      // Charge on FAILURE, not on arrival — the same treatment /login gets, for the same
      // reason (audit 2026-08-08 F-2). This bucket is keyed on a CALLER-SUPPLIED email,
      // and the client's "auto" mode sends every returning user through /register before
      // falling back to /login on 409. Charging on arrival let an unauthenticated
      // attacker naming a victim's email fill the bucket with free 409s, and the
      // victim's own /register then 429'd — which the auto flow treats as terminal, so
      // the fallback to /login never ran. A returning user's 409 must cost nothing, and
      // only a request that FAILS to prove possession may feed the counter (below).
      const registerBucket: RateLimitBucket = {
        endpoint: "register",
        appId,
        identifier: bucketId(body.email ?? body.publicKey),
      };

      if (await getUserByPublicKey(store, appId, body.publicKey)) {
        return error("Account already exists", 409);
      }
      // Email collision check. The client mints a fresh random publicKey on
      // every register attempt (Keypair.generate()), so without this check the
      // publicKey-only collision check above would never fire for email/
      // biometric signups, and every "Sign in or create account" attempt
      // would silently overwrite the email→publicKey index. Returning 409 here
      // lets the client's "auto" mode fall back to loginWithEmail and recover
      // the original publicKey (the appKey is deterministic, so decryption of
      // the original wallets still succeeds).
      // Per-APP email collision check: 409 only if THIS email already has an entry for
      // THIS appId. The same email on a different app is fine — registration adds a new
      // {appId -> publicKey} field to the shared email index instead of colliding (v0.4.0).
      if (body.email) {
        const existing = await resolvePublicKeyByEmail(store, appId, body.email);
        if (existing) return error("Account already exists", 409);
      }

      // Email/biometric accounts additionally store an auth key; a wallet account proves
      // itself by signature on every login and has none.
      if (body.authMethod !== "wallet" && !body.authPublicKey) {
        return error("authPublicKey required for email/biometric registration");
      }

      // 🚨 EVERY registration proves possession of the identity key — not just the wallet
      // path, which is how it used to be.
      //
      // The SDK's model is that an identity `publicKey` is either generated client-side by
      // this SDK or is the user's own connected wallet. Nothing enforced that: the
      // email/biometric branch accepted ANY well-formed base58 key. So a third party could
      // register at a victim's real on-chain address with `authMethod: "email"`, plant
      // attacker-controlled `wallets[]`, and wait. When the victim later connected that
      // wallet they authenticated correctly, landed in the planted record, had their own
      // generated bundle discarded (connectWallet only backfills an EMPTY record), and the
      // app then rendered the attacker's addresses as deposit addresses — useActiveWallet's
      // Web3 guard keys on `authMethod === "wallet"`, which the attacker had set to "email".
      //
      // The check costs an honest client nothing: it generated this keypair milliseconds
      // ago, so it signs automatically with no prompt. That it is invisible is not a
      // weakness — the proof is about KEY POSSESSION, not user attention, and an attacker
      // naming a key they do not hold simply cannot produce the bytes.
      //
      // Verify BEFORE consuming the single-use challenge, so a forged signature can't burn a
      // victim's pending challenge (matches login/loginWallet/connectWallet — WI-5).
      if (!body.signature || !body.challenge) return error("signature and challenge required");
      if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin)) {
        const limited = await rateLimited(req, registerBucket);
        if (limited) return limited;
        return error("Signature verification failed", 401);
      }
      if (!(await consumeChallenge(store, appId, body.publicKey, body.challenge))) {
        const limited = await rateLimited(req, registerBucket);
        if (limited) return limited;
        return error("Invalid or expired challenge", 401);
      }

      // Every collision check has passed, so this request WILL create a record. Charge the
      // deployment-wide ceiling here — not at the top — so a returning user's 409 (the
      // client's "auto" mode registers first, then falls back to login) costs nothing.
      const capped = await accountCreationLimited(req);
      if (capped) return capped;

      const user: UserData = {
        appId,
        publicKey: body.publicKey,
        email: body.email,
        authPublicKey: body.authPublicKey,
        authMethod: body.authMethod ?? "email",
        wallets,
        // PBKDF2 iteration count the client derived the app key with (email users);
        // pinned so the same count is used on every future login/unlock. Undefined for
        // wallet/biometric (they don't use PBKDF2).
        pbkdf2Iterations: body.pbkdf2Iterations,
        // Hardware wallets pin the off-chain layout they signed under; absent otherwise.
        offchainEnvelope: body.offchainEnvelope,
        // Real timestamp is stamped by the runtime; tests can inject via storage.
        createdAt: Date.now(),
      };
      // The collision check above is check-then-act, so two concurrent registrations for one
      // address both reach here. The STORE settles it atomically and throws for the loser;
      // answer that with the same 409 the pre-check produces, so the client's "auto" mode
      // falls back to login exactly as it would have.
      try {
        await persistUser(store, user);
      } catch (e) {
        if (e instanceof EmailTakenError) return error("Account already exists", 409);
        throw e;
      }
      const token = await issueSession(store, user, config, issueFingerprint(req));
      return json(asResult(user, token), 201);
    },

    async login(req) {
      const body = await readJson<{
        appId?: string;
        email?: string;
        signature?: string;
        challenge?: string;
      }>(req);
      if (!body?.email || !body.signature || !body.challenge) {
        return error("email, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      // Validate the email BEFORE it reaches a storage key (v0.5.0). /register has always
      // done this; /login did not, so an unauthenticated caller could submit a 1 MB
      // `email` and have it become a key. Inert on Redis (keys are unbounded and the
      // lookup just misses) — but on a SQL backend that is an unauthenticated 500
      // (Postgres) or a silent key truncation (non-strict MySQL). It also invalidates the
      // ≤320-byte bound every backend's column sizing is derived from. Rejects only input
      // that was already outside the documented format.
      const emailErr = validateEmail(body.email);
      if (emailErr) return error(emailErr);

      // Verify the signature FIRST, then rate-limit only on FAILURE. Two reasons:
      //  1. A valid login is never throttled, so an attacker spamming failed logins
      //     for a victim's email cannot lock the victim out of their own correct
      //     login — only failed attempts feed the counter (AUTHSESSION-3).
      //  2. We check the (storage-free) ed25519 signature before consuming the
      //     single-use challenge, so a junk signature can't burn a victim's pending
      //     challenge — only the real key-holder's request reaches consumeChallenge.
      // The server holds no passkey-derived secret; auth is proof-of-control of the key.
      const publicKey = await resolvePublicKeyByEmail(store, appId, body.email);
      const user = publicKey ? await getUserByPublicKey(store, appId, publicKey) : null;
      const sigValid =
        !!user?.authPublicKey && verifyAuthSignature(user.authPublicKey, body.signature, body.challenge);
      const consumed =
        sigValid && publicKey ? await consumeChallenge(store, appId, publicKey, body.challenge) : false;
      if (user && sigValid && consumed) {
        const token = await issueSession(store, user, config, issueFingerprint(req));
        return json(asResult(user, token));
      }
      const limited = await rateLimited(req, { endpoint: "login", appId, identifier: bucketId(body.email) });
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    async loginWallet(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        signature?: string;
        challenge?: string;
      }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);

      // Verify-first, penalize-on-failure (see login). A junk signature never
      // reaches consumeChallenge, so it can't burn a pending challenge, and a valid
      // wallet login is never throttled by an attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin);
      const consumed = sigValid
        ? await consumeChallenge(store, appId, body.publicKey, body.challenge)
        : false;
      if (sigValid && consumed) {
        const user = await getUserByPublicKey(store, appId, body.publicKey);
        // A valid signature proves key ownership; a missing account is not an attack,
        // so don't feed the failure counter — just report it.
        // 422, not 404. The request was well-formed AND the signature verified — the caller
        // genuinely holds this key — there is simply no account to log in to yet. 404 would
        // say the endpoint is missing; 400 would say the request was malformed, and it was
        // not; 401 would say the credential failed, and it did not. A distinct status lets a
        // client branch straight to registration instead of parsing the message.
        if (!user) return error("Wallet not registered", 422);
        const token = await issueSession(store, user, config, issueFingerprint(req));
        return json(asResult(user, token));
      }
      const limited = await rateLimited(req, {
        endpoint: "login",
        appId,
        identifier: body.publicKey,
      });
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    // Login-or-register for a Web3 wallet in one round trip. New wallets are
    // created with the client-provided encrypted bundle; existing wallets log in
    // (provided bundle ignored — their stored keys were encrypted with the same
    // deterministic key and must not be overwritten).
    async connectWallet(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        signature?: string;
        challenge?: string;
        wallets?: EncryptedWallet[];
        offchainEnvelope?: OffchainEnvelope;
      }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);
      if (body.offchainEnvelope != null && !validEnvelope(body.offchainEnvelope)) {
        return error("Invalid offchainEnvelope", 400);
      }
      let wallets: EncryptedWallet[] = [];
      if (body.wallets !== undefined) {
        const r = readWallets(body.wallets);
        if ("error" in r) return r.error;
        wallets = r.wallets;
      }

      // Verify-first, penalize-on-failure (see login): a junk signature can't burn
      // the challenge, and a returning wallet's valid connect isn't throttled by an
      // attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin);
      const consumed = sigValid
        ? await consumeChallenge(store, appId, body.publicKey, body.challenge)
        : false;
      if (!(sigValid && consumed)) {
        const limited = await rateLimited(req, {
          endpoint: "connect",
          appId,
          identifier: body.publicKey,
        });
        if (limited) return limited;
        return error("Invalid credentials", 401);
      }

      let user = await getUserByPublicKey(store, appId, body.publicKey);

      // Defence in depth: a WALLET login must not resolve a record the email/biometric path
      // created. Registration now proves possession of the identity key, so such a record
      // should not exist for a wallet the caller controls — but if one ever does (an older
      // record, a hand-rolled client), its `wallets[]` were never proven to belong to this
      // key, and handing them back is how an attacker-planted deposit address reaches the UI.
      // Fail closed rather than adopt a record we cannot vouch for.
      if (user && user.authMethod !== "wallet") return error("Invalid credentials", 401);

      const isNew = !user;
      if (!user) {
        // The other creation path. A valid signature is required to get here, but keypairs
        // are free to generate, so without this it is the same unbounded record creation
        // by a different door.
        const cappedNew = await accountCreationLimited(req);
        if (cappedNew) return cappedNew;
        user = {
          appId,
          publicKey: body.publicKey,
          authMethod: "wallet",
          wallets,
          offchainEnvelope: body.offchainEnvelope,
          createdAt: Date.now(),
        };
        await persistUser(store, user);
      } else if (!user.wallets?.length && wallets.length) {
        // Self-heal: an existing wallet with no stored keys yet (legacy/empty
        // record) gets backfilled from the client bundle. Safe — nothing to
        // overwrite. Wallets that already have keys are never touched.
        // Slot-scoped, for the same reason as import: never rewrite the whole record.
        for (const w of wallets) await store.putWalletSlot(user.appId, user.publicKey, w);
        user.wallets = wallets;
      }
      const token = await issueSession(store, user, config, issueFingerprint(req));
      return json(asResult(user, token), isNew ? 201 : 200);
    },

    // Revoke the current session. Always returns 200 { ok: true } and never leaks
    // whether the presented token was valid.
    async logout(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (appId && user && token) await revokeSession(store, appId, token);
      return json({ ok: true });
    },

    async userData(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (!user) return error("Unauthorized", 401);
      return json({ user: publicUser(user) });
    },

    async searchWallet(req) {
      const url = new URL(req.url);
      const publicKey = url.searchParams.get("publicKey");
      if (!publicKey) return error("publicKey required");
      const appId = url.searchParams.get("appId") ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(publicKey);
      if (pkErr) return error(pkErr);
      // Per-target rate limiting (see challenge): keyed by the queried (app, publicKey)
      // so one abuser can't exhaust a shared bucket and block all existence lookups.
      const limited = await rateLimited(req, { endpoint: "search", appId, identifier: publicKey });
      if (limited) return limited;
      const user = await getUserByPublicKey(store, appId, publicKey);
      // A SEARCH that matched nothing is a successful search, not a missing resource, so
      // it answers 200 with `exists: false` rather than 404. The query was well-formed and
      // ran; "no result" is the result. 404 would claim the endpoint itself is absent.
      //
      // NOTE: this does not close the enumeration oracle (audit.md L-3) — the body still
      // distinguishes a registered wallet from an unregistered one, which is the endpoint's
      // entire purpose. It only stops that answer being carried by a status code that means
      // something else.
      return json({ exists: !!user });
    },

    async importWallet(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (!user) return error("Unauthorized", 401);

      const body = await readJson<{ wallets?: EncryptedWallet[] }>(req);
      if (!body?.wallets?.length) return error("wallets required");
      const parsed = readWallets(body.wallets);
      if ("error" in parsed) return parsed.error;

      // REPLACE the (chain, role) slot — never append. Appending was a fund-misdirection
      // bug, not just bloat: `useActiveWallet` resolves a wallet with `.find()`, which
      // returns the FIRST match, while an appended import lands LAST. Importing an EVM
      // funds wallet therefore left the OLD address active, so the app kept displaying it
      // as the deposit address and kept signing with it — the user's replacement silently
      // did nothing. Replacing in place makes the record's four slots authoritative.
      // One slot-scoped write per wallet — NOT a whole-record rewrite. Writing the record
      // back wholesale is what destroyed keys: a concurrent login (which also rewrote it)
      // or a second import would resolve last-write-wins and drop the other's ciphertext,
      // silently, with both requests returning 200.
      for (const incoming of parsed.wallets) {
        await store.putWalletSlot(user.appId, user.publicKey, incoming);
      }
      const updated = (await getUserByPublicKey(store, user.appId, user.publicKey)) ?? user;
      return json({ user: publicUser(updated) });
    },
  };
}
