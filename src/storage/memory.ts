// In-memory adapter — for tests and quick prototyping. Not for production.
import type { StorageAdapter, SetOptions } from "./adapter.js";

interface Entry {
  value: string;
  expiresAt?: number;
}

export class MemoryAdapter implements StorageAdapter {
  private readonly store = new Map<string, Entry>();
  // Hashes live in their own map (the email→{appId:publicKey} index). No TTL — the
  // email index is permanent, like the plain-string value it replaced.
  private readonly hstore = new Map<string, Map<string, string>>();
  // Injectable clock so tests don't depend on Date.now() directly.
  constructor(private readonly now: () => number = () => Date.now()) {}

  private alive(key: string): Entry | undefined {
    const e = this.store.get(key);
    if (!e) return undefined;
    if (e.expiresAt != null && e.expiresAt <= this.now()) {
      this.store.delete(key);
      return undefined;
    }
    return e;
  }

  async get(key: string): Promise<string | null> {
    return this.alive(key)?.value ?? null;
  }

  async set(key: string, value: string, opts?: SetOptions): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: opts?.exSeconds ? this.now() + opts.exSeconds * 1000 : undefined,
    });
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }

  async incr(key: string): Promise<number> {
    const current = this.alive(key);
    const next = (current ? parseInt(current.value, 10) || 0 : 0) + 1;
    this.store.set(key, { value: String(next), expiresAt: current?.expiresAt });
    return next;
  }

  async expire(key: string, seconds: number): Promise<void> {
    const e = this.alive(key);
    if (e) e.expiresAt = this.now() + seconds * 1000;
  }

  async getdel(key: string): Promise<string | null> {
    const value = this.alive(key)?.value ?? null;
    this.store.delete(key);
    return value;
  }

  async hget(key: string, field: string): Promise<string | null> {
    return this.hstore.get(key)?.get(field) ?? null;
  }

  async hset(key: string, field: string, value: string): Promise<void> {
    let h = this.hstore.get(key);
    if (!h) {
      h = new Map();
      this.hstore.set(key, h);
    }
    h.set(field, value);
  }

  async hdel(key: string, field: string): Promise<void> {
    const h = this.hstore.get(key);
    if (h) {
      h.delete(field);
      if (h.size === 0) this.hstore.delete(key);
    }
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const h = this.hstore.get(key);
    return h ? Object.fromEntries(h) : {};
  }
}
