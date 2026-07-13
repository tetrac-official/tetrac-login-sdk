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

export interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: SetOptions): Promise<void>;
  del(key: string): Promise<void>;
  /** Atomic increment; returns the new value. Used for rate limiting. */
  incr(key: string): Promise<number>;
  /** Set/refresh a key's TTL in seconds. */
  expire(key: string, seconds: number): Promise<void>;
  /** Atomically get a key's value and delete it; used for single-use challenges. */
  getdel(key: string): Promise<string | null>;
  /** Read one field of a hash; null if the hash or field is absent. */
  hget(key: string, field: string): Promise<string | null>;
  /**
   * Set one field of a hash. Per-field writes are atomic, so two concurrent
   * registrations of the same email under different appIds never lose a write —
   * which is why the email index is a hash, not a JSON string (v0.4.0).
   */
  hset(key: string, field: string, value: string): Promise<void>;
  /** Delete one field of a hash (no-op if absent). */
  hdel(key: string, field: string): Promise<void>;
  /** Read the whole hash as a plain object; `{}` when the key is absent. */
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
