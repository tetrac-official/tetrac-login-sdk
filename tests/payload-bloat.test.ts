// H-2(a) (audit.md) — an anonymous request must not choose how much we store.
//
// `validateWallets` bounded `publicKey` (128) and `encryptedSecret` (8192) and checked
// `chain`, then the handler persisted the caller's object VERBATIM:
// `wallets: body.wallets ?? []` → `JSON.stringify(user)`. Validating known fields is not
// the same as storing only known fields — every unknown property rode along untouched.
//
// Measured before the fix: 5,000,403 bytes persisted by ONE anonymous POST /register,
// with every documented bound satisfied. Records have no TTL and nothing sweeps them, so
// that is permanent storage the attacker picked the size of — a cost-exhaustion attack on
// metered KV, and an OOM/eviction risk on Redis.
//
// The fix is to REBUILD each entry from an allowlist, so the stored size is a function of
// the bounds rather than of the request.
import { Keypair } from "@solana/web3.js";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { MAX_BODY_BYTES } from "../src/server/http";

const ORIGIN = "https://test.example";

function handlers(storage: MemoryAdapter) {
  return createAuthHandlers({ storage, config: { origin: ORIGIN } });
}

function post(body: unknown): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Total bytes persisted under this account, across every field of the record. */
async function storedBytes(storage: MemoryAdapter, publicKey: string): Promise<number> {
  const rec = await storage.hgetall(`pubKey:ttc:${publicKey}`);
  return Object.values(rec).reduce((n, v) => n + v.length, 0);
}

describe("H-2(a) — unknown wallet properties cannot inflate a record", () => {
  it("🚨 a padded wallet entry is stored stripped, not verbatim", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const publicKey = Keypair.generate().publicKey.toBase58();

    const res = await h.register(
      post({
        publicKey,
        email: "bloat@example.com",
        authPublicKey: "ab".repeat(32),
        wallets: [
          {
            chain: "solana",
            role: "funds",
            publicKey: "p",
            encryptedSecret: "c",
            // Under MAX_BODY_BYTES on purpose: this must prove STRIPPING, not the
            // transport cap (covered separately below). Every documented field bound is
            // still satisfied — which is exactly why validation alone never caught it.
            junk: "x".repeat(50_000),
          },
        ],
      }),
    );

    expect(res.status).toBe(201);
    expect(await storedBytes(storage, publicKey)).toBeLessThan(2_000);

    // The four contract fields survive; nothing else does.
    const rec = await storage.hgetall(`pubKey:ttc:${publicKey}`);
    const wallet = JSON.parse(rec["w:solana:funds"]!);
    expect(Object.keys(wallet).sort()).toEqual(["chain", "encryptedSecret", "publicKey", "role"]);
    expect(wallet.junk).toBeUndefined();
  });

  it("🚨 import-wallet strips too — a session holder cannot grow the record either", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const publicKey = Keypair.generate().publicKey.toBase58();

    const reg = await h.register(
      post({ publicKey, email: "imp@example.com", authPublicKey: "ab".repeat(32), wallets: [] }),
    );
    const { authToken } = await reg.json();
    const auth = { "ttc-auth-token": authToken, "ttc-public-key": publicKey };

    const res = await h.importWallet(
      new Request("http://localhost/api/auth", {
        method: "POST",
        headers: { "content-type": "application/json", ...auth },
        body: JSON.stringify({
          wallets: [
            {
              chain: "evm",
              role: "funds",
              publicKey: "0xabc",
              encryptedSecret: "ct",
              junk: "y".repeat(50_000), // under the body cap — this proves stripping
            },
          ],
        }),
      }),
    );

    expect(res.status).toBe(200);
    expect(await storedBytes(storage, publicKey)).toBeLessThan(2_000);

    // …and the response never echoes the padding back either.
    const body = await res.json();
    expect(JSON.stringify(body).length).toBeLessThan(2_000);
  });

  it("the worst-case legitimate record stays within its documented bound", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const publicKey = Keypair.generate().publicKey.toBase58();

    // All four slots at the 8192-char ciphertext bound — the largest record the server
    // will ever hold, and the number every backend's column sizing is derived from.
    const max = [
      { chain: "solana", role: "funds" },
      { chain: "solana", role: "signing" },
      { chain: "evm", role: "funds" },
      { chain: "evm", role: "signing" },
    ].map((s, i) => ({ ...s, publicKey: `pk${i}`, encryptedSecret: "z".repeat(8192) }));

    const res = await h.register(
      post({ publicKey, email: "max@example.com", authPublicKey: "ab".repeat(32), wallets: max }),
    );
    expect(res.status).toBe(201);

    const bytes = await storedBytes(storage, publicKey);
    expect(bytes).toBeGreaterThan(32_000); // it really did store all four
    expect(bytes).toBeLessThan(40_000); // ~33 KB, and bounded by the slots, not the caller
  });
});

describe("H-2(a) — the request body itself is bounded", () => {
  it("🚨 a body past the cap is refused before it is parsed", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const publicKey = Keypair.generate().publicKey.toBase58();

    const res = await h.register(
      post({
        publicKey,
        email: "huge@example.com",
        authPublicKey: "ab".repeat(32),
        wallets: [{ chain: "solana", role: "funds", publicKey: "p", encryptedSecret: "c" }],
        padding: "q".repeat(MAX_BODY_BYTES + 1),
      }),
    );

    expect(res.status).toBe(400);
    expect(await storedBytes(storage, publicKey)).toBe(0); // nothing persisted
  });
});
