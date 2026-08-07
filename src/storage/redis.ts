// ioredis adapter — for local development (redis://localhost:6379).
import type { StorageAdapter, SetOptions } from "./adapter.js";

/** Minimal structural type for an ioredis client, so we don't hard-depend on the types. */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, ttl?: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  getdel(key: string): Promise<string | null>;
  hget(key: string, field: string): Promise<string | null>;
  hset(key: string, field: string, value: string): Promise<unknown>;
  hsetnx(key: string, field: string, value: string): Promise<number>;
  hdel(key: string, field: string): Promise<unknown>;
  hgetall(key: string): Promise<Record<string, string>>;
  /** OPTIONAL so existing mocks (which have no quit) still satisfy this type. ioredis has it. */
  quit?(): Promise<unknown>;
}

export class RedisAdapter implements StorageAdapter {
  constructor(private readonly client: RedisLike) {}

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, opts?: SetOptions): Promise<void> {
    if (opts?.exSeconds) {
      await this.client.set(key, value, "EX", opts.exSeconds);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async incr(key: string): Promise<number> {
    return this.client.incr(key);
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.client.expire(key, seconds);
  }

  async getdel(key: string): Promise<string | null> {
    return this.client.getdel(key);
  }

  async hget(key: string, field: string): Promise<string | null> {
    return this.client.hget(key, field);
  }

  async hset(key: string, field: string, value: string): Promise<void> {
    await this.client.hset(key, field, value);
  }

  async hsetnx(key: string, field: string, value: string): Promise<boolean> {
    // Native HSETNX — one round trip, atomic on the server. Returns 1 when created.
    return (await this.client.hsetnx(key, field, value)) === 1;
  }

  async hdel(key: string, field: string): Promise<void> {
    await this.client.hdel(key, field);
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    // ioredis returns {} for a missing key, never null.
    return (await this.client.hgetall(key)) ?? {};
  }

  /**
   * Release the ioredis socket (v0.5.0). ioredis holds a live TCP connection, and until
   * now there was no way to release it: Jest hangs on the open handle, and a long-lived
   * Node/Express server leaks a connection per reload with no graceful-shutdown path.
   *
   * Idempotent, and safe against a client that has no `quit` (a mock, or a pooled client
   * the app owns and closes itself) — hence the feature-detect.
   */
  async close(): Promise<void> {
    await this.client.quit?.();
  }

  // No `sweepExpired()`: Redis expiry is native and exact, so there is nothing to
  // reclaim. Omitted deliberately.
}
