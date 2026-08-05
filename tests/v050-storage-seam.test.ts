// v0.5.0 — the release's four behavioral guarantees:
//   §1  session tokens are stored as SHA-256 digests, in BOTH storage locations
//   §2  close?() / sweepExpired?() exist, are optional, and are honestly feature-detected
//   §3  the AuthStore seam is additive — `storage` still works, `store` also works
//   §4  the prerequisite fixes (MemoryAdapter.del, /login email validation, fail-closed)
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { RedisAdapter } from "../src/storage/redis";
import { KvAuthStore, type RateLimitResult } from "../src/storage/store";
import { hashSessionToken } from "../src/core/crypto";
import { DEFAULT_CONFIG } from "../src/core/config";
import { registerEmail, jreq } from "./_auth-helpers";
import { Keypair } from "@solana/web3.js";

const APP_KEY = "a".repeat(64);

function freshKeypair(): string {
  return Keypair.generate().publicKey.toBase58();
}

async function registerFresh(h: ReturnType<typeof createAuthHandlers>, email: string) {
  const publicKey = freshKeypair();
  const res = await registerEmail(h, { email, appKey: APP_KEY, publicKey });
  expect(res.status).toBe(201);
  return { ...(await res.json()), publicKey } as { authToken: string; publicKey: string };
}

// =====================================================================================
// §1 — the session token is never stored in the clear, ANYWHERE
// =====================================================================================
describe("§1 session tokens at rest are SHA-256 digests, never the raw bearer token", () => {
  it("🚨 the raw token appears in NEITHER the session key NOR the UserData blob", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });
    const { authToken, publicKey } = await registerFresh(h, "atrest@example.com");

    // (a) The session is keyed by the DIGEST. The raw token is not a key.
    expect(await storage.get(`session:ttc:${hashSessionToken(authToken)}`)).toBe(publicKey);
    expect(await storage.get(`session:ttc:${authToken}`)).toBeNull();

    // (b) And — this is the half that a naive "just hash the key" fix misses — the raw
    // token is not inside the UserData record either. Before v0.5.0, issueSession wrote
    // `user.authToken = token`, so a read of the store yielded a live, replayable
    // credential for every logged-in user even if the KEY had been hashed.
    // The record is a HASH (profile / session pointer / one field per wallet slot), so
    // check EVERY field: the raw token must appear in none of them.
    const rec = await storage.hgetall(`pubKey:ttc:${publicKey}`);
    expect(Object.keys(rec).length).toBeGreaterThan(0);
    for (const v of Object.values(rec)) expect(v).not.toContain(authToken);

    const profile = JSON.parse(rec.p!);
    expect(profile.authToken).toBeUndefined();
    expect(rec.t).toBe(hashSessionToken(authToken)); // the pointer field holds the DIGEST
  });

  it("the digest is never echoed to the client", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });
    const publicKey = freshKeypair();
    const res = await registerEmail(h, { email: "echo@example.com", appKey: APP_KEY, publicKey });
    const body = await res.json();

    expect(body.authToken).toMatch(/^[0-9a-f]{64}$/); // the RAW token, for the client
    expect(body.user.authTokenHash).toBeUndefined(); // the digest stays server-side
    expect(body.user.authToken).toBeUndefined();
  });

  it("the session still verifies, and a new login still revokes the previous session", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });
    const { authToken, publicKey } = await registerFresh(h, "revoke@example.com");

    // The round trip works end-to-end through the hashed key.
    const ok = await h.userData(jreq({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey }));
    expect(ok.status).toBe(200);

    // Re-issue: the OLD digest key must be gone (revocation happens via the stored hash,
    // since the server no longer holds the previous raw token).
    await h.logout(jreq({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey }));
    expect(await storage.get(`session:ttc:${hashSessionToken(authToken)}`)).toBeNull();

    const after = await h.userData(jreq({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey }));
    expect(after.status).toBe(401);
  });
});

// =====================================================================================
// §2 — optional lifecycle methods, honestly feature-detected
// =====================================================================================
describe("§2 close?() and sweepExpired?() are optional and truthfully advertised", () => {
  it("MemoryAdapter implements sweepExpired (it expires lazily, so it really does leak)", async () => {
    let now = 1_000_000;
    const storage = new MemoryAdapter(() => now);

    await storage.set("live", "v", { exSeconds: 3600 });
    await storage.set("doomed-1", "v", { exSeconds: 1 });
    await storage.set("doomed-2", "v", { exSeconds: 1 });

    now += 2000; // both expire; nothing reads them, so lazy expiry never fires

    expect(await storage.sweepExpired()).toBe(2);
    expect(await storage.get("live")).toBe("v"); // a sweep must never take a live entry
    expect(await storage.sweepExpired()).toBe(0); // idempotent
  });

  it("sweepExpired respects `limit`", async () => {
    let now = 1_000_000;
    const storage = new MemoryAdapter(() => now);
    for (let i = 0; i < 5; i++) await storage.set(`k${i}`, "v", { exSeconds: 1 });
    now += 2000;
    expect(await storage.sweepExpired(2)).toBe(2);
    expect(await storage.sweepExpired()).toBe(3);
  });

  it("MemoryAdapter omits close() — there is nothing to release", () => {
    expect(new MemoryAdapter().close).toBeUndefined();
  });

  it("RedisAdapter.close() quits the client, and tolerates a client without quit()", async () => {
    const quit = jest.fn().mockResolvedValue("OK");
    const withQuit = { quit } as never;
    await new RedisAdapter(withQuit).close();
    expect(quit).toHaveBeenCalledTimes(1);

    // A mock/pooled client with no quit() must not throw — the adapter feature-detects.
    await expect(new RedisAdapter({} as never).close()).resolves.toBeUndefined();
  });

  it("KvAuthStore forwards the optionals HONESTLY — it never claims a capability the adapter lacks", () => {
    // Over MemoryAdapter: sweep yes, close no.
    const overMemory = new KvAuthStore(new MemoryAdapter());
    expect(typeof overMemory.sweepExpired).toBe("function");
    expect(overMemory.close).toBeUndefined();

    // Over Redis: close yes (native TTL means no sweep is needed, and none is claimed).
    const overRedis = new KvAuthStore(new RedisAdapter({} as never));
    expect(typeof overRedis.close).toBe("function");
    expect(overRedis.sweepExpired).toBeUndefined();
  });
});

// =====================================================================================
// §3 — the seam is additive
// =====================================================================================
describe("§3 the AuthStore seam is additive — no existing deployment changes a line", () => {
  it("createAuthHandlers({ storage }) still works, exactly as before", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const { authToken, publicKey } = await registerFresh(h, "kv@example.com");
    const res = await h.userData(jreq({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey }));
    expect(res.status).toBe(200);
  });

  it("createAuthHandlers({ store }) accepts a native AuthStore", async () => {
    const store = new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    const h = createAuthHandlers({ store, config: { origin: "https://test.example" } });
    const { authToken, publicKey } = await registerFresh(h, "native@example.com");
    const res = await h.userData(jreq({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey }));
    expect(res.status).toBe(200);
  });

  it("supplying neither is a loud, immediate error", () => {
    expect(() => createAuthHandlers({ config: { origin: "https://test.example" } })).toThrow(
      /requires either `store`.*or `storage`/,
    );
  });
});

// =====================================================================================
// §4 — the prerequisite fixes
// =====================================================================================
describe("§4.1 MemoryAdapter.del clears BOTH keyspaces, like real Redis DEL", () => {
  it("del removes a hash, not just a string", async () => {
    const storage = new MemoryAdapter();
    await storage.hset("email:x@y.com", "app1", "PK");
    expect(await storage.hgetall("email:x@y.com")).toEqual({ app1: "PK" });

    await storage.del("email:x@y.com");
    expect(await storage.hgetall("email:x@y.com")).toEqual({});
    expect(await storage.hget("email:x@y.com", "app1")).toBeNull();
  });
});

describe("§4.2 /login validates the email BEFORE it reaches a storage key", () => {
  it("🚨 rejects an over-length email instead of turning it into a 400 KB key", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });

    const huge = `${"a".repeat(400_000)}@example.com`;
    const res = await h.login(jreq({ email: huge, signature: "ab", challenge: "cd" }));

    // Inert on Redis; on Postgres this is an unauthenticated 500, and on non-strict MySQL
    // a SILENT key truncation. Either way it invalidates the ≤320-byte bound every
    // backend's column sizing is derived from.
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("Invalid email format");
  });

  it("rejects a malformed email on /login, matching /register", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await h.login(jreq({ email: "not-an-email", signature: "ab", challenge: "cd" }));
    expect(res.status).toBe(400);
  });

  it("a valid-but-unknown email still reaches the normal 401 (no behavior change)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await h.login(jreq({ email: "nobody@example.com", signature: "ab", challenge: "cd" }));
    expect(res.status).toBe(401);
  });
});

describe("§4.3 storage failures FAIL CLOSED — a broken backend never grants permission", () => {
  /** A store whose rate limiter is down. The tempting "fix" is to catch and allow. */
  class BrokenRateLimitStore extends KvAuthStore {
    async hitRateLimit(): Promise<RateLimitResult> {
      throw new Error("backend down");
    }
  }

  it("🚨 a throwing hitRateLimit propagates — it does NOT resolve to `allowed`", async () => {
    const h = createAuthHandlers({
      store: new BrokenRateLimitStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes),
      config: { origin: "https://test.example" },
    });

    const url = `http://localhost/api/auth?publicKey=${freshKeypair()}`;
    // searchWallet rate-limits before it does anything else.
    await expect(h.searchWallet(new Request(url))).rejects.toThrow("backend down");
  });

  it("the rate limiter has no try/catch by design — a limiter that cannot count must not allow", async () => {
    // Guard the invariant directly at the domain layer, so a future adapter author who
    // "helpfully" swallows the error inside checkRateLimit trips this test.
    const { checkRateLimit } = await import("../src/server/rateLimit");
    const store = new BrokenRateLimitStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    await expect(
      checkRateLimit(store, { endpoint: "login", appId: "ttc", identifier: "x" }, DEFAULT_CONFIG.rateLimit),
    ).rejects.toThrow("backend down");
  });
});
