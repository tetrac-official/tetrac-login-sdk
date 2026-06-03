// In-memory adapter — for tests and quick prototyping. Not for production.
import type { StorageAdapter, SetOptions } from "./adapter.js";

interface Entry {
  value: string;
  expiresAt?: number;
}

export class MemoryAdapter implements StorageAdapter {
  private readonly store = new Map<string, Entry>();
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
}
