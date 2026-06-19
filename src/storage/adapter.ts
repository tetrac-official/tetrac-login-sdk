// Storage abstraction. Injected into the server layer so the client bundle never
// pulls in a database client. Every backend implements this minimal surface.

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
}
