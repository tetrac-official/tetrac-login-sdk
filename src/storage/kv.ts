// Adapter for @vercel/kv and @upstash/redis — both expose the same surface
// (get / set with { ex } / del / incr / expire), so one adapter covers both.
import type { StorageAdapter, SetOptions } from "./adapter.js";

export interface KvLike {
  get<T = string>(key: string): Promise<T | null>;
  set(key: string, value: string, opts?: { ex?: number }): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
}

class KvAdapter implements StorageAdapter {
  constructor(private readonly client: KvLike) {}

  async get(key: string): Promise<string | null> {
    const v = await this.client.get<string>(key);
    if (v == null) return null;
    // Both clients may auto-deserialize; coerce back to a string for our string-only values.
    return typeof v === "string" ? v : String(v);
  }

  async set(key: string, value: string, opts?: SetOptions): Promise<void> {
    await this.client.set(key, value, opts?.exSeconds ? { ex: opts.exSeconds } : undefined);
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

/** Wrap a @vercel/kv `kv` instance. */
export class VercelKVAdapter extends KvAdapter {}

/** Wrap an @upstash/redis `Redis` instance. */
export class UpstashAdapter extends KvAdapter {}
