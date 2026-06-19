// Multi-app Upstash isolation (v0.4.0). One MemoryAdapter stands in for one shared
// Redis/Upstash DB; two appIds register/log in over it and must never read, overwrite,
// or authenticate into each other's records. Also covers the {appId -> publicKey}
// email map, appId validation, and the per-app rate-limit / challenge / session scoping.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { walletLoginMessage } from "../src/core/index";
import { registerEmail, loginEmail } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32);
const APP_A = "app.alpha";
const APP_B = "app.beta";
// Two distinct, canonical Solana public keys (the email "identity" key differs per app,
// just as the client mints a fresh keypair per registration).
const PK_A = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const PK_B = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

describe("email accounts: same email isolated per app", () => {
  it("registers the same email independently on two apps (no false 409)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "shared@example.com";

    const a = await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A });
    const b = await registerEmail(h, { appId: APP_B, email, appKey: APP_KEY, publicKey: PK_B });

    expect(a.status).toBe(201);
    expect(b.status).toBe(201); // would be 409 under a global email index
    expect((await a.json()).publicKey).toBe(PK_A);
    expect((await b.json()).publicKey).toBe(PK_B);
  });

  it("the email index is a {appId -> publicKey} map (the requested shape)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "map@example.com";
    await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A });
    await registerEmail(h, { appId: APP_B, email, appKey: APP_KEY, publicKey: PK_B });

    expect(await storage.hgetall(`email:${email}`)).toEqual({ [APP_A]: PK_A, [APP_B]: PK_B });
  });

  it("re-registering the same email on the SAME app still 409s", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "dupe@example.com";
    expect((await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A })).status).toBe(
      201,
    );
    const again = await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_B });
    expect(again.status).toBe(409);
  });

  it("login resolves the per-app identity; the wrong app cannot log in", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "login@example.com";
    await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A });

    // App A logs in fine and recovers PK_A.
    const ok = await loginEmail(h, { appId: APP_A, email, appKey: APP_KEY });
    expect(ok.status).toBe(200);
    expect((await ok.json()).publicKey).toBe(PK_A);

    // App B has no account for this email: it can't even resolve the identity to issue
    // a challenge, so the flow never reaches a 200. (No cross-app record is visible.)
    const bChallenge = await h.challenge(req({ appId: APP_B, email }));
    expect(bChallenge.status).toBe(400); // unknown email under app B → no challenge
    const bad = await loginEmail(h, { appId: APP_B, email, appKey: APP_KEY });
    expect(bad.status).not.toBe(200);
  });

  it("pubKey records are stored under disjoint app-scoped keys", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "scoped@example.com";
    await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A });

    expect(await storage.get(`pubKey:${APP_A}:${PK_A}`)).not.toBeNull();
    expect(await storage.get(`pubKey:${APP_B}:${PK_A}`)).toBeNull(); // not visible to app B
    expect(await storage.get(`pubKey:${PK_A}`)).toBeNull(); // never the legacy flat key
  });
});

describe("wallet accounts: same wallet, independent per-app records", () => {
  async function connect(
    h: ReturnType<typeof createAuthHandlers>,
    appId: string,
    kp: Keypair,
    wallets: unknown[],
  ) {
    const pubKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(req({ appId, publicKey: pubKey }))).json();
    const sig = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge)), kp.secretKey),
    );
    return h.connectWallet(req({ appId, publicKey: pubKey, signature: sig, challenge, wallets }));
  }

  it("the same wallet on two apps keeps each app's own encrypted bundle", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();

    const a = await connect(h, APP_A, kp, [
      { chain: "solana", role: "funds", publicKey: pubKey, encryptedSecret: "CT_A" },
    ]);
    const b = await connect(h, APP_B, kp, [
      { chain: "solana", role: "funds", publicKey: pubKey, encryptedSecret: "CT_B" },
    ]);

    // Both are NEW creations (201) — app B is not mistaken for a returning app-A user.
    expect(a.status).toBe(201);
    expect(b.status).toBe(201);
    expect((await a.json()).user.wallets[0].encryptedSecret).toBe("CT_A");
    expect((await b.json()).user.wallets[0].encryptedSecret).toBe("CT_B"); // not CT_A
  });

  it("a challenge issued for one app does not satisfy another", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();

    // Register the wallet on app A so it has a record to log into.
    await connect(h, APP_A, kp, []);

    // Get a challenge under app A, but try to spend it under app B.
    const { challenge } = await (await h.challenge(req({ appId: APP_A, publicKey: pubKey }))).json();
    const sig = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge)), kp.secretKey),
    );
    const crossApp = await h.loginWallet(req({ appId: APP_B, publicKey: pubKey, signature: sig, challenge }));
    expect(crossApp.status).toBe(401); // app-B challenge keyspace never held it
  });
});

describe("session scoping across apps", () => {
  it("a token minted by one app is rejected by another", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const email = "sess@example.com";
    const reg = await registerEmail(h, { appId: APP_A, email, appKey: APP_KEY, publicKey: PK_A });
    const { authToken, publicKey } = await reg.json();

    // Correct app → 200.
    const okHeaders = { "ttc-auth-token": authToken, "ttc-public-key": publicKey, "ttc-app-id": APP_A };
    expect((await h.userData(req({}, okHeaders))).status).toBe(200);

    // Same token, wrong app header → 401 (session key is app-scoped).
    const crossHeaders = { "ttc-auth-token": authToken, "ttc-public-key": publicKey, "ttc-app-id": APP_B };
    expect((await h.userData(req({}, crossHeaders))).status).toBe(401);
  });
});

describe("appId validation", () => {
  it("rejects an appId containing the ':' key separator", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await registerEmail(h, { appId: "a:b", email: "x@y.com", appKey: APP_KEY, publicKey: PK_A });
    expect(res.status).toBe(400);
  });

  it("rejects an overlong appId", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await registerEmail(h, {
      appId: "a".repeat(65),
      email: "x@y.com",
      appKey: APP_KEY,
      publicKey: PK_A,
    });
    expect(res.status).toBe(400);
  });

  it("with allowedAppIds set, an undeclared appId is rejected", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { allowedAppIds: [APP_A] },
    });
    const ok = await registerEmail(h, { appId: APP_A, email: "ok@y.com", appKey: APP_KEY, publicKey: PK_A });
    expect(ok.status).toBe(201);
    const bad = await registerEmail(h, { appId: APP_B, email: "no@y.com", appKey: APP_KEY, publicKey: PK_B });
    expect(bad.status).toBe(400);
  });
});

describe("single-app backward compatibility (no appId supplied)", () => {
  it("omitting appId falls back to config.appId (default 'ttc') and round-trips", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const reg = await registerEmail(h, { email: "legacy@example.com", appKey: APP_KEY, publicKey: PK_A });
    expect(reg.status).toBe(201);
    // Stored under the default app namespace.
    expect(await storage.get(`pubKey:ttc:${PK_A}`)).not.toBeNull();
    const login = await loginEmail(h, { email: "legacy@example.com", appKey: APP_KEY });
    expect(login.status).toBe(200);
  });
});
