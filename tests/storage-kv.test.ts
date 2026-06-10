// B1 (KV deserialization) + H3 (atomic getdel) storage-adapter tests.
//
// In prod both @vercel/kv and @upstash/redis auto-deserialize JSON, so a stored
// UserData blob comes back as an OBJECT. The KvAdapter must re-stringify so the
// JSON.parse consumers in server/session.ts round-trip cleanly.
import { VercelKVAdapter, UpstashAdapter, type KvLike } from "../src/storage/kv";
import { MemoryAdapter } from "../src/storage/memory";

// KV-like mock that auto-deserializes: get()/getdel() return the PARSED value
// (whatever was passed to set), mimicking @vercel/kv and @upstash/redis.
function mockKv(): KvLike {
  const store = new Map<string, unknown>();
  const parse = (raw: string): unknown => {
    try {
      return JSON.parse(raw);
    } catch {
      return raw; // not JSON — return the string as-is
    }
  };
  return {
    async get<T = string>(key: string) {
      return (store.has(key) ? (store.get(key) as T) : null) as T | null;
    },
    async set(key: string, value: string) {
      store.set(key, parse(value));
      return "OK";
    },
    async del(key: string) {
      store.delete(key);
      return 1;
    },
    async incr(key: string) {
      const next = ((store.get(key) as number) ?? 0) + 1;
      store.set(key, next);
      return next;
    },
    async expire() {
      return 1;
    },
    async getdel<T = string>(key: string) {
      const v = store.has(key) ? (store.get(key) as T) : null;
      store.delete(key);
      return v as T | null;
    },
  };
}

describe("KvAdapter (B1) — auto-deserialized JSON round-trip", () => {
  it("get() re-stringifies an object value so JSON.parse(get()) deep-equals it", async () => {
    const adapter = new VercelKVAdapter(mockKv());
    const blob = {
      publicKey: "SoLPubKey1111111111111111111111111111111111",
      email: "user@example.com",
      wallets: [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "c" }],
      createdAt: 1234,
    };

    await adapter.set("pubKey:abc", JSON.stringify(blob));
    const raw = await adapter.get("pubKey:abc");

    expect(typeof raw).toBe("string"); // never "[object Object]"
    expect(raw).not.toBe("[object Object]");
    expect(JSON.parse(raw as string)).toEqual(blob);
  });

  it("returns plain strings unchanged (e.g. email->pubKey index)", async () => {
    const adapter = new UpstashAdapter(mockKv());
    await adapter.set("email:user", "SoLPubKey1111111111111111111111111111111111");
    expect(await adapter.get("email:user")).toBe("SoLPubKey1111111111111111111111111111111111");
  });

  it("returns null for a missing key", async () => {
    const adapter = new VercelKVAdapter(mockKv());
    expect(await adapter.get("nope")).toBeNull();
  });

  it("getdel re-stringifies an object value and removes it", async () => {
    const adapter = new UpstashAdapter(mockKv());
    const blob = { challenge: "deadbeef", n: 1 };
    await adapter.set("challenge:abc", JSON.stringify(blob));

    const raw = await adapter.getdel("challenge:abc");
    expect(JSON.parse(raw as string)).toEqual(blob);
    expect(await adapter.get("challenge:abc")).toBeNull();
  });
});

describe("MemoryAdapter.getdel (H3) — atomic single-use", () => {
  it("returns the value once then null (two sequential getdel -> one hit)", async () => {
    const adapter = new MemoryAdapter();
    await adapter.set("challenge:abc", "the-challenge");

    const first = await adapter.getdel("challenge:abc");
    const second = await adapter.getdel("challenge:abc");

    expect(first).toBe("the-challenge");
    expect(second).toBeNull();
  });

  it("getdel on a missing key returns null", async () => {
    const adapter = new MemoryAdapter();
    expect(await adapter.getdel("missing")).toBeNull();
  });

  it("concurrent getdel of the same key yields exactly one non-null", async () => {
    const adapter = new MemoryAdapter();
    await adapter.set("challenge:race", "v");
    const [a, b] = await Promise.all([adapter.getdel("challenge:race"), adapter.getdel("challenge:race")]);
    const hits = [a, b].filter((x) => x !== null);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toBe("v");
  });
});
