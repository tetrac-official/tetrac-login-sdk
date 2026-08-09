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
    // Real Redis DEL removes a key of ANY type, so it clears both keyspaces. Before
    // v0.5.0 this deleted only from `store`, silently diverging from RedisAdapter —
    // unobservable (no caller dels an email-index key) but enough to make this class's
    // "normative reference implementation" status untrue. Fixed.
    this.store.delete(key);
    this.hstore.delete(key);
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

  async hsetnx(key: string, field: string, value: string): Promise<boolean> {
    let h = this.hstore.get(key);
    if (!h) {
      h = new Map();
      this.hstore.set(key, h);
    }
    // Single-threaded JS with no await between the check and the set — genuinely atomic.
    if (h.has(field)) return false;
    h.set(field, value);
    return true;
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

  /**
   * Reclaim expired entries (v0.5.0). This adapter expires LAZILY — `alive()` only
   * deletes an entry when something reads it — and rate-limit counters, abandoned
   * challenges, and expired sessions are typically NEVER read again. So a long-running
   * process (a dev server, a soak test) grows monotonically. That is a real leak, and
   * this is its fix.
   *
   * Space only: correctness never depends on it, because `alive()` already hides an
   * expired entry from every read path.
   */
  async sweepExpired(limit?: number): Promise<number> {
    const now = this.now();
    let removed = 0;
    for (const [key, entry] of this.store) {
      if (limit !== undefined && removed >= limit) break;
      if (entry.expiresAt != null && entry.expiresAt <= now) {
        this.store.delete(key); // safe: Map iteration tolerates deletion of the current entry
        removed++;
      }
    }
    return removed;
  }

  // No `close()`: there is nothing to release. Omitted deliberately, so that callers'
  // feature-detection (`await storage.close?.()`) is exercised against an adapter that
  // genuinely lacks it.
}
