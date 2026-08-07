// The KV storage port — a Redis-shaped key/value surface.
//
// NOTE (v0.5.0): this is NO LONGER the SDK's primary extension point. The server layer
// now talks to `AuthStore` (./store.ts), the DOMAIN port. `StorageAdapter` remains the
// contract for backends that genuinely ARE Redis-style KV stores — i.e. that have
// native atomic INCR, native TTL, and atomic GETDEL — and `KvAuthStore` wraps any of
// them into an AuthStore.
//
// If you are backing the SDK with a real database (Postgres, Mongo, DynamoDB, Convex,
// Durable Objects), implement `AuthStore` instead. Emulating these primitives on an
// engine that has better tools is how you get the permanent-rate-limit-lockout bug.
// See PRD/ADR-001-storage-seam.md.

export interface SetOptions {
  /** Expire the key after this many seconds. */
  exSeconds?: number;
}

/**
 * A Redis-shaped KV backend.
 *
 * THE CONTRACT IS NOT "whatever Redis happens to do" — it is the four invariants below.
 * They are the ones a reasonable implementation gets WRONG on the first try, and each
 * failure is silent: the adapter passes a smoke test and then, days later, permanently
 * locks a user out or accepts an expired session. `MemoryAdapter` is the normative
 * reference implementation (and is verified against a real Redis in CI) — when this
 * comment and `MemoryAdapter` disagree, `MemoryAdapter` is right.
 *
 *  (1) AN EXPIRED KEY IS INDISTINGUISHABLE FROM AN ABSENT KEY, on EVERY read path
 *      (`get`, `getdel`, `incr`). Expiry is enforced ON READ. A TTL index, cron, or
 *      `sweepExpired` is space reclamation ONLY and is never the expiry authority.
 *
 *  (2) `incr` ON AN EXPIRED KEY RETURNS 1 — a fresh counter, with the stale TTL dropped.
 *      🚨 This is the load-bearing one. `checkRateLimit` infers "first hit of a new
 *      window" from `count === 1` and only then stamps the TTL. An implementation that
 *      increments a stale counter (the obvious SQL upsert returns 16, not 1) never
 *      stamps the new window — and that IP / email / public key is rate-limited FOREVER.
 *      It will not show up in any smoke test: it only appears after a window elapses.
 *
 *  (3) `incr` ON A LIVE KEY PRESERVES ITS EXISTING TTL — never extends it, never clears
 *      it. Refreshing the TTL on every hit turns a fixed window into a sliding one that
 *      an attacker under sustained load can keep alive indefinitely.
 *
 *  (4) `expire` ON AN ABSENT OR EXPIRED KEY IS A NO-OP. It must never create a row or
 *      resurrect a dead one.
 *
 * Plus: `del` removes the key from BOTH keyspaces (real Redis `DEL` is type-agnostic),
 * and errors PROPAGATE — `null` means "the backend answered, and the key is absent",
 * never "the backend did not answer". Verify with `@tetrac/login-sdk/storage/conformance`.
 */
export interface StorageAdapter {
  /** null when the key is absent OR EXPIRED (invariant 1). */
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: SetOptions): Promise<void>;
  /** Removes the key from BOTH the string and the hash keyspace, like real Redis `DEL`. */
  del(key: string): Promise<void>;
  /**
   * Atomic increment; returns the new value. Backs rate limiting.
   *
   * 🚨 On an EXPIRED key this MUST return 1 and drop the stale TTL (invariant 2), and on
   * a LIVE key it MUST leave the existing TTL untouched (invariant 3). Getting either
   * wrong produces a PERMANENT rate-limit lockout, not a subtle drift.
   */
  incr(key: string): Promise<number>;
  /** Set/refresh a key's TTL in seconds. A no-op on an absent/expired key (invariant 4). */
  expire(key: string, seconds: number): Promise<void>;
  /**
   * ATOMICALLY get a key's value and delete it. Backs single-use login challenges, and is
   * the SOLE mechanism closing the challenge-replay race: of N concurrent callers, exactly
   * ONE may observe the value. A get-then-delete pair is NOT sufficient.
   * Returns null when absent OR expired (invariant 1).
   */
  getdel(key: string): Promise<string | null>;
  /** Read one field of a hash; null if the hash or field is absent. */
  hget(key: string, field: string): Promise<string | null>;
  /**
   * Set one field of a hash. Per-field writes MUST be atomic, so two concurrent
   * registrations of the same email under different appIds never lose a write —
   * which is why the email index is a hash, not a JSON string (v0.4.0). An
   * implementation that reads the hash, merges in memory, and writes it back
   * reintroduces exactly the race this design exists to eliminate.
   */
  hset(key: string, field: string, value: string): Promise<void>;
  /**
   * Set one field ONLY IF IT DOES NOT EXIST. Returns true when this call created it.
   *
   * 🚨 MUST be atomic — this is the email index's claim operation, and the entire defence
   * against two concurrent registrations for one address. `hset` alone is last-write-wins:
   * both callers pass the handler's "is this email taken?" check, both write, and the loser's
   * account still EXISTS but is no longer reachable by email — its owner cannot log in, and
   * their wallets are encrypted under a key only they hold.
   *
   * Redis `HSETNX`. Do NOT emulate it with hget-then-hset: that is the race, restated.
   */
  hsetnx(key: string, field: string, value: string): Promise<boolean>;
  /** Delete one field of a hash (no-op if absent). */
  hdel(key: string, field: string): Promise<void>;
  /** Read the whole hash as a plain object; `{}` — never null — when the key is absent. */
  hgetall(key: string): Promise<Record<string, string>>;

  // --- OPTIONAL lifecycle (v0.5.0). Callers MUST feature-detect: `await x.close?.()` ---

  /**
   * OPTIONAL. Delete expired entries; returns how many were removed. `limit` bounds one
   * batch.
   *
   * SPACE RECLAMATION ONLY — this is NEVER the expiry authority. Every adapter must
   * already make an expired entry invisible on the READ path whether or not this has
   * ever run. An adapter that relies on a sweep for correctness is non-conformant.
   * Adapters with native, exact expiry (Redis, Upstash, Vercel KV) omit it.
   */
  sweepExpired?(limit?: number): Promise<number>;

  /**
   * OPTIONAL. Release pooled connections / handles. Idempotent — calling it twice is
   * safe, and calling it on an adapter that never opened anything is a no-op. Adapters
   * over a stateless REST client (Upstash, Vercel KV) or an in-process Map omit it.
   */
  close?(): Promise<void>;
}
