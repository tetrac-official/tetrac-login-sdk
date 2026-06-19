// Hash ops (hget/hset/hdel/hgetall) added in v0.4.0 for the email→{appId:publicKey}
// index. Verified across all three production adapter shapes: MemoryAdapter, the
// ioredis-style RedisAdapter, and the KV/Upstash adapter (which may auto-deserialize).
import { MemoryAdapter } from "../src/storage/memory";
import { RedisAdapter, type RedisLike } from "../src/storage/redis";
import { UpstashAdapter, type KvLike } from "../src/storage/kv";
import type { StorageAdapter } from "../src/storage/adapter";

// ioredis-style mock: hset(key, field, value), hgetall returns {} when absent.
function mockRedis(): RedisLike {
  const hashes = new Map<string, Map<string, string>>();
  const strings = new Map<string, string>();
  return {
    async get(k) {
      return strings.get(k) ?? null;
    },
    async set(k, v) {
      strings.set(k, v);
      return "OK";
    },
    async del(k) {
      strings.delete(k);
      hashes.delete(k);
      return 1;
    },
    async incr(k) {
      const n = (parseInt(strings.get(k) ?? "0", 10) || 0) + 1;
      strings.set(k, String(n));
      return n;
    },
    async expire() {
      return 1;
    },
    async getdel(k) {
      const v = strings.get(k) ?? null;
      strings.delete(k);
      return v;
    },
    async hget(k, f) {
      return hashes.get(k)?.get(f) ?? null;
    },
    async hset(k, f, v) {
      let h = hashes.get(k);
      if (!h) hashes.set(k, (h = new Map()));
      h.set(f, v);
      return 1;
    },
    async hdel(k, f) {
      hashes.get(k)?.delete(f);
      return 1;
    },
    async hgetall(k) {
      const h = hashes.get(k);
      return h ? Object.fromEntries(h) : {};
    },
  };
}

// KV/Upstash-style mock: hset(key, { [field]: value }) object form; values may come
// back parsed (auto-deserialize). hgetall returns null when the key is absent.
function mockKv(): KvLike {
  const hashes = new Map<string, Map<string, unknown>>();
  const strings = new Map<string, unknown>();
  const parse = (raw: string): unknown => {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  };
  return {
    async get<T = string>(k: string) {
      return (strings.has(k) ? (strings.get(k) as T) : null) as T | null;
    },
    async set(k: string, v: string) {
      strings.set(k, parse(v));
      return "OK";
    },
    async del(k: string) {
      strings.delete(k);
      hashes.delete(k);
      return 1;
    },
    async incr(k: string) {
      const n = ((strings.get(k) as number) ?? 0) + 1;
      strings.set(k, n);
      return n;
    },
    async expire() {
      return 1;
    },
    async getdel<T = string>(k: string) {
      const v = strings.has(k) ? (strings.get(k) as T) : null;
      strings.delete(k);
      return v as T | null;
    },
    async hget<T = string>(k: string, f: string) {
      const h = hashes.get(k);
      return (h && h.has(f) ? (h.get(f) as T) : null) as T | null;
    },
    async hset(k: string, kv: Record<string, unknown>) {
      let h = hashes.get(k);
      if (!h) hashes.set(k, (h = new Map()));
      for (const [f, v] of Object.entries(kv)) h.set(f, parse(String(v)));
      return Object.keys(kv).length;
    },
    async hdel(k: string, ...fields: string[]) {
      const h = hashes.get(k);
      for (const f of fields) h?.delete(f);
      return fields.length;
    },
    async hgetall<T = Record<string, unknown>>(k: string) {
      const h = hashes.get(k);
      return (h ? (Object.fromEntries(h) as T) : null) as T | null;
    },
  };
}

const adapters: Array<[string, () => StorageAdapter]> = [
  ["MemoryAdapter", () => new MemoryAdapter()],
  ["RedisAdapter", () => new RedisAdapter(mockRedis())],
  ["UpstashAdapter", () => new UpstashAdapter(mockKv())],
];

describe.each(adapters)("hash ops — %s", (_name, make) => {
  it("hset then hget round-trips a single field", async () => {
    const s = make();
    await s.hset("email:u@x.com", "appA", "PubKeyA");
    expect(await s.hget("email:u@x.com", "appA")).toBe("PubKeyA");
  });

  it("hget returns null for an absent field or absent key", async () => {
    const s = make();
    expect(await s.hget("missing", "appA")).toBeNull();
    await s.hset("email:u@x.com", "appA", "PubKeyA");
    expect(await s.hget("email:u@x.com", "appB")).toBeNull();
  });

  it("hgetall returns the full {field: value} map", async () => {
    const s = make();
    await s.hset("email:u@x.com", "appA", "PubKeyA");
    await s.hset("email:u@x.com", "appB", "PubKeyB");
    expect(await s.hgetall("email:u@x.com")).toEqual({ appA: "PubKeyA", appB: "PubKeyB" });
  });

  it("hgetall on an absent key is an empty object (never null)", async () => {
    expect(await make().hgetall("nope")).toEqual({});
  });

  it("hset overwrites a field in place (no duplicate)", async () => {
    const s = make();
    await s.hset("k", "appA", "first");
    await s.hset("k", "appA", "second");
    expect(await s.hget("k", "appA")).toBe("second");
    expect(await s.hgetall("k")).toEqual({ appA: "second" });
  });

  it("hdel removes one field but leaves the others", async () => {
    const s = make();
    await s.hset("k", "appA", "A");
    await s.hset("k", "appB", "B");
    await s.hdel("k", "appA");
    expect(await s.hget("k", "appA")).toBeNull();
    expect(await s.hgetall("k")).toEqual({ appB: "B" });
  });
});
