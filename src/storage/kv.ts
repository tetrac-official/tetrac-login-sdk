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
  // @upstash/redis and @vercel/kv both take the field map as an OBJECT on hset,
  // and may auto-deserialize values on read (hence the coerce() in the adapter).
  hget<T = string>(key: string, field: string): Promise<T | null>;
  hset(key: string, kv: Record<string, unknown>): Promise<unknown>;
  hdel(key: string, ...fields: string[]): Promise<unknown>;
  hgetall<T = Record<string, unknown>>(key: string): Promise<T | null>;
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

  async hget(key: string, field: string): Promise<string | null> {
    return this.coerce(await this.client.hget<string>(key, field));
  }

  async hset(key: string, field: string, value: string): Promise<void> {
    await this.client.hset(key, { [field]: value });
  }

  async hdel(key: string, field: string): Promise<void> {
    await this.client.hdel(key, field);
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const all = await this.client.hgetall<Record<string, unknown>>(key);
    if (!all) return {};
    const out: Record<string, string> = {};
    for (const [field, value] of Object.entries(all)) {
      const c = this.coerce(value);
      if (c != null) out[field] = c;
    }
    return out;
  }
}

/** Wrap a @vercel/kv `kv` instance. */
export class VercelKVAdapter extends KvAdapter {}

/** Wrap an @upstash/redis `Redis` instance. */
export class UpstashAdapter extends KvAdapter {}
