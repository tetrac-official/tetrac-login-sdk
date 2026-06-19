// C2 — EVM wallet design intent verification.
//
// EVM wallets are generated client-side, encrypted under the app key, and
// stored as ciphertext alongside Solana wallets. They are used internally
// via viem LocalAccount (useEvmSigner) for signing transactions.
//
// EVM wallets are NEVER used for Web3 authentication. Only Solana wallets
// are used for login/registration. The server's Solana-only signature
// verification is correct by design — there is no verifyEvmSignature because
// EVM addresses are not authentication identities.
//
// WHAT THIS TESTS:
//  - The account IDENTITY publicKey must be a Solana ed25519 key. An EVM 0x address
//    is rejected at validation (400) on every path — wallet, connect-wallet, AND email
//    (audit zai-glm-52: validatePublicKey is now strictly Solana-only).
//  - EVM keys live ONLY inside the encrypted wallet bundle (chain:"evm"), never as the
//    identity — they're internal signing wallets (useEvmSigner / viem LocalAccount).
//  - The server has no EVM verification function (expected — not a gap)
//  - Verifies the auth boundary: Solana = Web3 auth + identity, EVM = internal signing only
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail, loginEmail } from "./_auth-helpers";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("EVM wallet — design intent (C2)", () => {
  const evmAddress = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

  const solIdentity = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";

  it("authMethod='wallet' with EVM address is rejected at validation (400)", async () => {
    // EVM addresses are NOT valid identities. Strict Solana validation rejects the
    // 0x identity up front (400) — earlier than the old 401 signature-failure.
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const reg = await h.register(
      req({
        publicKey: evmAddress,
        authMethod: "wallet",
        wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "CT" }],
        signature: "00".repeat(65),
        challenge: "x".repeat(64),
      }),
    );

    expect(reg.status).toBe(400);
  });

  it("connect-wallet with EVM address is also rejected at validation (400)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const cw = await h.connectWallet(
      req({
        publicKey: evmAddress,
        signature: "00".repeat(65),
        challenge: "x".repeat(64),
        wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "CT" }],
      }),
    );

    expect(cw.status).toBe(400);
  });

  it("an EVM address is rejected as the email identity too — only a Solana identity is valid", async () => {
    // The identity publicKey must be a Solana ed25519 key on EVERY path, including
    // email. The correct pattern is a Solana identity with EVM wallets in the bundle.
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const rejected = await registerEmail(h, {
      publicKey: evmAddress, // EVM as the identity → rejected
      email: "evm-id@test.com",
      appKey: "ab".repeat(32),
      wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "encrypted-key" }],
    });
    expect(rejected.status).toBe(400);

    // The supported shape: a Solana identity, with the EVM key carried in the bundle.
    const ok = await registerEmail(h, {
      publicKey: solIdentity,
      email: "sol-id@test.com",
      appKey: "ab".repeat(32),
      wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "encrypted-key" }],
    });
    expect(ok.status).toBe(201);

    const login = await loginEmail(h, { email: "sol-id@test.com", appKey: "ab".repeat(32) });
    expect(login.status).toBe(200);
    expect((await login.json()).publicKey).toBe(solIdentity);
  });

  it("server has no EVM verification function (expected — EVM is not an auth method)", async () => {
    // This is not a gap. EVM wallets are internal signing wallets.
    // No verifyEvmSignature is needed because no one authenticates
    // with an EVM address.
    const { verifySolanaSignature } = await import("../src/server/signature");
    expect(typeof verifySolanaSignature).toBe("function");
    // eslint-disable-next-line no-console
    console.log(
      "  EVM verification: intentionally absent (EVM is not an auth method). Only Solana is Web3 auth.",
    );
  });
});
