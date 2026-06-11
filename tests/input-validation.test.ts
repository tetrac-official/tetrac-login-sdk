// C8 — Input validation gap detection.
//
// WHAT THIS TESTS:
//  - Missing email format validation (any string accepted)
//  - Missing passkeyHash hex format validation
//  - Missing publicKey format validation (could be anything)
//  - Missing challenge format validation
//  - Wallets array bounded (max 16) but individual string fields unchecked
//  - Special characters, very long strings, edge cases
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";

function req(body: unknown): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("email validation gaps (C8)", () => {
  it("accepts empty string as email", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol1111111111111111111111111111111111111",
      email: "",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [],
    }));
    // Empty email is accepted — no format validation at all
    expect(res.status).toBe(201);
  });

  it("accepts malicious payload as email", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol2222222222222222222222222222222222222",
      email: "javascript:alert(1)@foo.com", // XSS vector if reflected in UI
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [],
    }));
    // Should ideally validate email format (RFC 5321)
    expect(res.status).toBe(201);
  });

  it("accepts extremely long email", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const longEmail = "a".repeat(10_000) + "@b.com";
    const res = await h.register(req({
      publicKey: "Sol3333333333333333333333333333333333333",
      email: longEmail,
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [],
    }));
    // Very long email is accepted — could cause storage issues
    expect(res.status).toBe(201);
  });
});

describe("passkeyHash validation gaps", () => {
  it("accepts non-hex passkeyHash", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol4444444444444444444444444444444444444",
      email: "user@test.com",
      passkeyHash: "this is NOT hex!!!", // garbage
      authMethod: "email",
      wallets: [],
    }));
    // No hex format validation — any string accepted
    expect(res.status).toBe(201);
  });

  it("accepts empty passkeyHash (length 0)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol5555555555555555555555555555555555555",
      email: "empty@test.com",
      passkeyHash: "", // empty string — passes truthiness check
      authMethod: "email",
      wallets: [],
    }));
    // Empty string IS falsey, so the else-if check at routes.ts:142
    // would trigger for authMethod !== "wallet" and return 400.
    // BUT if authMethod is "wallet" and the user has an EVM address,
    // the empty string situation is different.
    expect(res.status).toBe(400); // empty string is falsey, so caught
  });

  it("accepts passkeyHash shorter than 64 hex chars", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol6666666666666666666666666666666666666",
      email: "short@test.com",
      passkeyHash: "abc123", // only 6 chars, not 64
      authMethod: "email",
      wallets: [],
    }));
    // Accepted — no length validation on passkeyHash
    // SHA-256 output should always be 64 hex chars
    expect(res.status).toBe(201);
  });
});

describe("publicKey validation gaps", () => {
  it("accepts arbitrary string as publicKey for email auth", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "   \n\t  ", // whitespace-only
      email: "pk@test.com",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [],
    }));
    // Whitespace-only publicKey is accepted
    expect(res.status).toBe(201);
  });

  it("accepts very long publicKey", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const longPk = "x".repeat(100_000);
    const res = await h.register(req({
      publicKey: longPk,
      email: "longpk@test.com",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [{ chain: "solana", role: "funds", publicKey: longPk, encryptedSecret: "c" }],
    }));
    // No length check — could strain storage
    expect(res.status).toBe(201);
  });
});

describe("challenge validation gaps", () => {
  it("accepts arbitrary string as challenge for wallet registration", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const pk = "Sol1111111111111111111111111111111111111";

    // Issue a real challenge so the key exists
    const chRes = await h.challenge(req({ publicKey: pk }));
    const { challenge } = await chRes.json();

    // Now try with a tampered challenge
    const res = await h.register(req({
      publicKey: pk,
      authMethod: "wallet",
      wallets: [],
      signature: "00".repeat(64),
      challenge: challenge + "tampered", // modified challenge
    }));

    // consumeChallenge uses timingSafeEqual, so a modified challenge
    // will fail and return 401. The gap is that there's no format
    // validation before the comparison — the comparison itself is
    // the validation. This is acceptable behavior.
    expect(res.status).toBe(401);
  });
});

describe("wallet payload validation", () => {
  it("accepts wallet with empty encryptedSecret", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req({
      publicKey: "Sol7777777777777777777777777777777777777",
      email: "wallets@test.com",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets: [{ chain: "solana", role: "funds", publicKey: "pk", encryptedSecret: "" }],
    }));
    // Empty encryptedSecret is accepted — should have minimum length check
    expect(res.status).toBe(201);
  });

  it("wallets array with more than 16 entries rejected", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const wallets = Array.from({ length: 17 }, () => ({
      chain: "solana" as const,
      role: "funds",
      publicKey: "pk",
      encryptedSecret: "c",
    }));
    const res = await h.register(req({
      publicKey: "Sol8888888888888888888888888888888888888",
      email: "many@test.com",
      passkeyHash: "a".repeat(64),
      authMethod: "email",
      wallets,
    }));
    // The validateWallets function checks length > 16
    expect(res.status).toBe(400);
  });
});
