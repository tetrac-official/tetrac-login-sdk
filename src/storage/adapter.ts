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
}
