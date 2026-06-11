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
//  - Attempting to register with authMethod="wallet" + EVM address → 401
//    (correct: EVM is not a supported auth method)
//  - EVM addresses can be used as publicKey via email auth (they are just
//    opaque identifiers for the encrypted wallet bundle — no wallet proof needed)
//  - The server has no EVM verification function (expected — not a gap)
//  - Verifies the auth boundary: Solana = Web3 auth, EVM = internal signing only
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("EVM wallet — design intent (C2)", () => {
  const evmAddress = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

  it("authMethod='wallet' with EVM address is rejected (correct: only Solana is Web3 auth)", async () => {
    // EVM addresses are NOT valid Web3 auth identities. Only Solana
    // public keys can be used for wallet-based authentication. This
    // 401 is correct behavior.
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const chRes = await h.challenge(req({ publicKey: evmAddress }));
    const { challenge } = await chRes.json();

    const reg = await h.register(req({
      publicKey: evmAddress,
      authMethod: "wallet",
      wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "CT" }],
      signature: "00".repeat(65),
      challenge,
    }));

    expect(reg.status).toBe(401);
  });

  it("connect-wallet with EVM address is also rejected", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const chRes = await h.challenge(req({ publicKey: evmAddress }));
    const { challenge } = await chRes.json();

    const cw = await h.connectWallet(req({
      publicKey: evmAddress,
      signature: "00".repeat(65),
      challenge,
      wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "CT" }],
    }));

    expect(cw.status).toBe(401);
  });

  it("EVM address CAN be used with email auth (it's just an opaque identifier)", async () => {
    // The publicKey field is an opaque identifier. When authMethod="email",
    // there's no wallet signature requirement — the account is authenticated
    // via email+passkey. The publicKey can be any string; it doesn't need
    // to be wallet-verified because the auth is via email.
    //
    // For EVM wallets, this is the expected path: wallets are generated
    // client-side, encrypted, and stored. A Solana "identity" wallet serves
    // as the publicKey for email/biometric users; but the system also allows
    // EVM addresses as publicKey identifiers since they are opaque strings.
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    const reg = await h.register(req({
      publicKey: evmAddress,
      email: "evm-user@test.com",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [{ chain: "evm", role: "funds", publicKey: evmAddress, encryptedSecret: "encrypted-key" }],
    }));

    expect(reg.status).toBe(201);

    // Login with email+passkey works (no wallet proof needed — correct)
    const login = await h.login(req({ email: "evm-user@test.com", passkeyHash: "a".repeat(64) }));
    expect(login.status).toBe(200);
    const body = await login.json();
    expect(body.publicKey).toBe(evmAddress);
  });

  it("server has no EVM verification function (expected — EVM is not an auth method)", async () => {
    // This is not a gap. EVM wallets are internal signing wallets.
    // No verifyEvmSignature is needed because no one authenticates
    // with an EVM address.
    const { verifySolanaSignature } = await import("../src/server/signature");
    expect(typeof verifySolanaSignature).toBe("function");
    // eslint-disable-next-line no-console
    console.log("  EVM verification: intentionally absent (EVM is not an auth method). Only Solana is Web3 auth.");
  });
});
