import { MemoryAdapter } from "../src/storage/memory";
import { selectStorageBackend } from "../src/storage/resolve";

describe("MemoryAdapter", () => {
  it("get/set/del round-trips", async () => {
    const s = new MemoryAdapter();
    await s.set("k", "v");
    expect(await s.get("k")).toBe("v");
    await s.del("k");
    expect(await s.get("k")).toBeNull();
  });

  it("incr counts and starts from zero", async () => {
    const s = new MemoryAdapter();
    expect(await s.incr("c")).toBe(1);
    expect(await s.incr("c")).toBe(2);
  });

  it("honors TTL via an injected clock", async () => {
    let now = 1_000_000;
    const s = new MemoryAdapter(() => now);
    await s.set("k", "v", { exSeconds: 5 });
    expect(await s.get("k")).toBe("v");
    now += 6_000; // advance 6s
    expect(await s.get("k")).toBeNull();
  });
});

// WI-10 (SERVERSIDE-10): selectStorageBackend is PURE (no client construction), so the
// production safety-guard is testable without opening a Redis connection.
describe("selectStorageBackend — production storage guard (WI-10)", () => {
  const ENV_KEYS = [
    "NODE_ENV",
    "REDIS_URL",
    "VERCEL",
    "KV_REST_API_URL",
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
  ];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = {};
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("production + NO backend env → throws (refuses the localhost fallback)", () => {
    process.env.NODE_ENV = "production";
    expect(() => selectStorageBackend()).toThrow(/No storage backend configured in production/);
  });

  it("production + REDIS_URL → ioredis with that URL (no throw)", () => {
    process.env.NODE_ENV = "production";
    process.env.REDIS_URL = "redis://prod-host:6379";
    expect(selectStorageBackend()).toEqual({ kind: "ioredis", url: "redis://prod-host:6379" });
  });

  it("dev + no env → ioredis localhost fallback (unchanged)", () => {
    process.env.NODE_ENV = "development";
    expect(selectStorageBackend()).toEqual({ kind: "ioredis", url: "redis://localhost:6379" });
  });

  it("Upstash URL + token → upstash", () => {
    process.env.UPSTASH_REDIS_REST_URL = "https://u.upstash.io";
    process.env.UPSTASH_REDIS_REST_TOKEN = "tok";
    expect(selectStorageBackend()).toEqual({ kind: "upstash" });
  });

  it("VERCEL / KV_REST_API_URL → vercelkv", () => {
    process.env.KV_REST_API_URL = "https://kv";
    expect(selectStorageBackend()).toEqual({ kind: "vercelkv" });
  });

  it("partial Upstash (URL without TOKEN) → warns, and in production still throws", () => {
    process.env.NODE_ENV = "production";
    process.env.UPSTASH_REDIS_REST_URL = "https://u.upstash.io"; // token missing
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    expect(() => selectStorageBackend()).toThrow(/No storage backend/);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("UPSTASH_REDIS_REST_TOKEN is missing"));
    warn.mockRestore();
  });
});
