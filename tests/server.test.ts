import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { hashPasskey } from "../src/core/crypto";
import { walletLoginMessage } from "../src/core/index";

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

describe("email auth flow", () => {
  it("registers then logs in with the same passkey hash", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const passkeyHash = hashPasskey("derived-app-key");

    const reg = await h.register(
      req({
        publicKey: "SoLPubKey1111111111111111111111111111111111",
        email: "user@example.com",
        passkeyHash,
        authMethod: "email",
        wallets: [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "c" }],
      }),
    );
    expect(reg.status).toBe(201);
    const regBody = await reg.json();
    expect(regBody.authToken).toHaveLength(64);

    const login = await h.login(req({ email: "user@example.com", passkeyHash }));
    expect(login.status).toBe(200);
    const loginBody = await login.json();
    expect(loginBody.publicKey).toBe(regBody.publicKey);

    const bad = await h.login(req({ email: "user@example.com", passkeyHash: "wrong" }));
    expect(bad.status).toBe(401);
  });
});

describe("wallet auth flow", () => {
  it("verifies a real ed25519 signature over the challenge", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();

    // 1. challenge
    const chRes = await h.challenge(req({ publicKey: pubKey }));
    const { challenge } = await chRes.json();
    expect(challenge).toHaveLength(64);

    // 2. sign the canonical message
    const message = new TextEncoder().encode(walletLoginMessage(challenge));
    const signature = bytesToHex(nacl.sign.detached(message, kp.secretKey));

    // 3. register the wallet (proves ownership)
    const reg = await h.register(
      req({ publicKey: pubKey, authMethod: "wallet", wallets: [], signature, challenge }),
    );
    expect(reg.status).toBe(201);

    // 4. fresh challenge + login
    const ch2 = await (await h.challenge(req({ publicKey: pubKey }))).json();
    const sig2 = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(ch2.challenge)), kp.secretKey),
    );
    const login = await h.loginWallet(req({ publicKey: pubKey, signature: sig2, challenge: ch2.challenge }));
    expect(login.status).toBe(200);
  });

  it("rejects a forged signature", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(req({ publicKey: pubKey }))).json();
    const res = await h.register(
      req({ publicKey: pubKey, authMethod: "wallet", wallets: [], signature: "00".repeat(64), challenge }),
    );
    expect(res.status).toBe(401);
  });
});

describe("connect-wallet (upsert)", () => {
  async function connect(h: ReturnType<typeof createAuthHandlers>, kp: Keypair, wallets: unknown[]) {
    const pubKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(req({ publicKey: pubKey }))).json();
    const sig = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge)), kp.secretKey),
    );
    return h.connectWallet(req({ publicKey: pubKey, signature: sig, challenge, wallets }));
  }

  it("creates a new wallet (201) then logs the same wallet in (200) without overwriting keys", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const kp = Keypair.generate();
    const original = [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "ORIGINAL" }];

    const first = await connect(h, kp, original);
    expect(first.status).toBe(201);

    // Returning connect ignores the provided bundle and keeps the stored keys.
    const second = await connect(h, kp, [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "ATTACKER" }]);
    expect(second.status).toBe(200);
    const body = await second.json();
    expect(body.user.wallets[0].encryptedSecret).toBe("ORIGINAL");
  });

  it("backfills wallets for an existing record that has none (self-heal)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const kp = Keypair.generate();

    const first = await connect(h, kp, []); // created with no wallets
    expect(first.status).toBe(201);
    expect((await first.json()).user.wallets).toHaveLength(0);

    const fresh = [{ chain: "evm", role: "funds", publicKey: "0xabc", encryptedSecret: "CT" }];
    const second = await connect(h, kp, fresh);
    expect(second.status).toBe(200);
    expect((await second.json()).user.wallets).toHaveLength(1);
  });
});

describe("rate limiting", () => {
  it("blocks after maxAttempts within the window", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { rateLimit: { maxAttempts: 3, windowSeconds: 60 } } });
    const make = () => h.challenge(req({ publicKey: "k" }, { "x-forwarded-for": "1.2.3.4" }));
    expect((await make()).status).toBe(200);
    expect((await make()).status).toBe(200);
    expect((await make()).status).toBe(200);
    expect((await make()).status).toBe(429); // 4th exceeds limit
  });
});

// --- Fable audit hardening (docs/5-PRD-FABLE-AUDIT.md) ---

// Register an email user and return { h, storage, body, passkeyHash }.
async function registerEmailUser(opts?: Parameters<typeof createAuthHandlers>[0]) {
  const storage = opts?.storage ?? new MemoryAdapter();
  const h = createAuthHandlers({ ...opts, storage });
  const passkeyHash = hashPasskey("derived-app-key");
  const reg = await h.register(
    req({
      publicKey: "SoLPubKey1111111111111111111111111111111111",
      email: "user@example.com",
      passkeyHash,
      authMethod: "email",
      wallets: [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "c" }],
    }),
  );
  const body = await reg.json();
  return { h, storage, body, passkeyHash };
}

describe("session lifecycle (H1)", () => {
  it("issues the session key with the configured TTL in the store", async () => {
    // Injectable clock: the session key must expire after sessionTtlSeconds.
    let now = 1_000_000;
    const storage = new MemoryAdapter(() => now);
    const { body } = await registerEmailUser({
      storage,
      config: { sessionTtlSeconds: 100 },
    });
    const sessionStoreKey = `pubKey:session:${body.authToken}`;

    expect(await storage.get(sessionStoreKey)).toBe(body.publicKey); // alive now
    now += 99_000; // still inside the 100s TTL
    expect(await storage.get(sessionStoreKey)).toBe(body.publicKey);
    now += 2_000; // past the TTL
    expect(await storage.get(sessionStoreKey)).toBeNull(); // expired
  });

  it("a new login revokes the previous session token", async () => {
    const { h, storage, body, passkeyHash } = await registerEmailUser();
    const firstToken = body.authToken;
    expect(await storage.get(`pubKey:session:${firstToken}`)).toBe(body.publicKey);

    const login = await h.login(req({ email: "user@example.com", passkeyHash }));
    const loginBody = await login.json();
    expect(loginBody.authToken).not.toBe(firstToken);
    // Old token is revoked; only the new one resolves.
    expect(await storage.get(`pubKey:session:${firstToken}`)).toBeNull();
    expect(await storage.get(`pubKey:session:${loginBody.authToken}`)).toBe(body.publicKey);
  });

  it("logout revokes the presented session token and always returns 200 { ok }", async () => {
    const { h, storage, body } = await registerEmailUser();
    const token = body.authToken;
    expect(await storage.get(`pubKey:session:${token}`)).toBe(body.publicKey);

    const res = await h.logout(
      req({}, { "ttc-auth-token": token, "ttc-public-key": body.publicKey }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(await storage.get(`pubKey:session:${token}`)).toBeNull(); // revoked
  });
});

describe("timing-safe credential compare (H2)", () => {
  it("accepts the correct passkey hash and rejects a wrong one", async () => {
    const { h, passkeyHash } = await registerEmailUser();
    const good = await h.login(req({ email: "user@example.com", passkeyHash }));
    expect(good.status).toBe(200);
    const bad = await h.login(
      req({ email: "user@example.com", passkeyHash: hashPasskey("not-the-key") }),
    );
    expect(bad.status).toBe(401);
  });
});

describe("atomic challenge consume (H3)", () => {
  it("a second login-wallet reusing the same challenge fails (challenge consumed)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();

    // Register the wallet so login-wallet has a record to resolve.
    const { challenge } = await (await h.challenge(req({ publicKey: pubKey }))).json();
    const sig = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge)), kp.secretKey),
    );
    const reg = await h.register(
      req({ publicKey: pubKey, authMethod: "wallet", wallets: [], signature: sig, challenge }),
    );
    expect(reg.status).toBe(201);

    // New challenge, log in once (consumes it), then replay the SAME challenge.
    const ch2 = await (await h.challenge(req({ publicKey: pubKey }))).json();
    const sig2 = bytesToHex(
      nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(ch2.challenge)), kp.secretKey),
    );
    const first = await h.loginWallet(req({ publicKey: pubKey, signature: sig2, challenge: ch2.challenge }));
    expect(first.status).toBe(200);
    const replay = await h.loginWallet(
      req({ publicKey: pubKey, signature: sig2, challenge: ch2.challenge }),
    );
    expect(replay.status).toBe(401); // challenge already consumed
  });
});

describe("response sanitization (H4)", () => {
  it("never echoes passkeyHash and the nested user has no authToken", async () => {
    const reg = await registerEmailUser();
    const text = JSON.stringify(reg.body);
    expect(text).not.toContain("passkeyHash");
    expect(reg.body.user.passkeyHash).toBeUndefined();
    expect(reg.body.user.authToken).toBeUndefined();
    // The token still travels top-level on the AuthResult.
    expect(typeof reg.body.authToken).toBe("string");

    // /user-data response is also sanitized.
    const ud = await reg.h.userData(
      req({}, { "ttc-auth-token": reg.body.authToken, "ttc-public-key": reg.body.publicKey }),
    );
    const udBody = await ud.json();
    expect(JSON.stringify(udBody)).not.toContain("passkeyHash");
    expect(udBody.user.authToken).toBeUndefined();
  });
});

describe("search-wallet hardening (M2)", () => {
  it("returns 429 after maxAttempts (IP rate limited)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { rateLimit: { maxAttempts: 2, windowSeconds: 60 } } });
    const search = () =>
      h.searchWallet(new Request("http://localhost/api/auth/search-wallet?publicKey=k"));
    expect((await search()).status).toBe(404); // not found, but allowed
    expect((await search()).status).toBe(404);
    expect((await search()).status).toBe(429); // 3rd exceeds the limit
  });
});

describe("wallet payload validation (M3)", () => {
  const valid = { chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "c" };

  it("rejects register with more than 16 wallets (400)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const wallets = Array.from({ length: 17 }, () => valid);
    const res = await h.register(
      req({ publicKey: "k", email: "a@b.com", passkeyHash: "h", authMethod: "email", wallets }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a malformed wallet entry (bad chain) (400)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({
        publicKey: "k",
        email: "a@b.com",
        passkeyHash: "h",
        authMethod: "email",
        wallets: [{ chain: "bitcoin", role: "funds", publicKey: "p", encryptedSecret: "c" }],
      }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a wallet entry missing required fields (400)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({
        publicKey: "k",
        email: "a@b.com",
        passkeyHash: "h",
        authMethod: "email",
        wallets: [{ chain: "solana", role: "funds", publicKey: "p" }], // no encryptedSecret
      }),
    );
    expect(res.status).toBe(400);
  });
});

describe("proxy-header trust (M4)", () => {
  it("with trustProxyHeaders default false, x-forwarded-for does not change the rate-limit identity", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { rateLimit: { maxAttempts: 2, windowSeconds: 60 } } });
    // Different spoofed IPs each request — they all share the "unknown" bucket
    // because the proxy header is untrusted, so the limit still trips.
    const make = (ip: string) => h.challenge(req({ publicKey: "k" }, { "x-forwarded-for": ip }));
    expect((await make("1.1.1.1")).status).toBe(200);
    expect((await make("2.2.2.2")).status).toBe(200);
    expect((await make("3.3.3.3")).status).toBe(429); // spoofing the IP didn't help
  });
});
