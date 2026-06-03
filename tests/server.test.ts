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
