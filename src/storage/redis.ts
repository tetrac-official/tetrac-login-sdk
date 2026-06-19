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
  hdel(key: string, field: string): Promise<unknown>;
  hgetall(key: string): Promise<Record<string, string>>;
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

  async hdel(key: string, field: string): Promise<void> {
    await this.client.hdel(key, field);
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    // ioredis returns {} for a missing key, never null.
    return (await this.client.hgetall(key)) ?? {};
  }
}
