// ioredis adapter — for local development (redis://localhost:6379).
import type { StorageAdapter, SetOptions } from "./adapter.js";

/** Minimal structural type for an ioredis client, so we don't hard-depend on the types. */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, ttl?: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
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
}
