// Adapter for @vercel/kv and @upstash/redis — both expose the same surface
// (get / set with { ex } / del / incr / expire), so one adapter covers both.
import type { StorageAdapter, SetOptions } from "./adapter.js";

export interface KvLike {
  get<T = string>(key: string): Promise<T | null>;
  set(key: string, value: string, opts?: { ex?: number }): Promise<unknown>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  getdel<T = string>(key: string): Promise<T | null>;
}

class KvAdapter implements StorageAdapter {
  constructor(private readonly client: KvLike) {}

  // Both clients may auto-deserialize JSON, so a stored blob comes back as an object.
  // Return strings as-is and re-stringify everything else so it round-trips through JSON.parse.
  private coerce(v: unknown): string | null {
    if (v == null) return null;
    return typeof v === "string" ? v : JSON.stringify(v);
  }

  async get(key: string): Promise<string | null> {
    return this.coerce(await this.client.get<string>(key));
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

  async getdel(key: string): Promise<string | null> {
    return this.coerce(await this.client.getdel<string>(key));
  }
}

/** Wrap a @vercel/kv `kv` instance. */
export class VercelKVAdapter extends KvAdapter {}

/** Wrap an @upstash/redis `Redis` instance. */
export class UpstashAdapter extends KvAdapter {}
