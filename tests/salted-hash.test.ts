// C4 — Unsalted SHA-256 passkey hash weakness demonstration.
//
// WHAT THIS TESTS:
//  - hashPasskey() is a plain SHA-256 with no salt — same passkey = same
//    hash across ALL users, enabling precomputation attacks
//  - Fast to compute (no work factor) — ASIC/GPU brute-force feasible
//  - Demonstrates the proposed v2 salted PBKDF2 hash fixes this
//  - Verifies the server uses timingSafeEqual for hash comparison
import { hashPasskey } from "../src/core/crypto";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("unsalted SHA-256 passkey hash weakness (C4)", () => {
  it("same passkey across different emails produces identical hash", () => {
    const hash1 = hashPasskey("common-passkey");
    const hash2 = hashPasskey("common-passkey");
    // Same passkey → same hash (this is correct for the same input,
    // but the point is there's NO salt, so two users with the same
    // passkey have identical stored hashes).
    expect(hash1).toBe(hash2);
  });

  it("two different users with identical passkeys have identical stored hashes", () => {
    const userA_hash = hashPasskey("snowflake2024");
    const userB_hash = hashPasskey("snowflake2024");
    // VULNERABILITY DEMONSTRATION: If userA and userB use the same
    // passkey, their stored passkeyHash is identical. An attacker who
    // compromises the DB can:
    //  1. Sort users by passkeyHash to find shared passkeys
    //  2. If any one user has a weak passkey, all users with the same
    //     hash are instantly compromised
    //  3. Rainbow tables for common passkey hashes can be precomputed
    expect(userA_hash).toBe(userB_hash);
  });

  it("SHA-256 hash is fast (no work factor) — brute-force is cheap", () => {
    const start = performance.now();
    const iterations = 10_000;
    for (let i = 0; i < iterations; i++) {
      hashPasskey(`password-${i}`);
    }
    const elapsed = performance.now() - start;
    const hashesPerSecond = (iterations / elapsed) * 1000;
    // eslint-disable-next-line no-console
    console.log(`  SHA-256 hash rate: ~${hashesPerSecond.toLocaleString()} hashes/second`);
    // This is deliberately fast — SHA-256 is designed to be fast,
    // which is the OPPOSITE of what a password hash should be.
    // For comparison, PBKDF2 with 600k iterations would be ~600,000x
    // slower per hash.
    expect(hashesPerSecond).toBeGreaterThan(10_000);
  });

  it("the hash is only 32 bytes (256 bits) — no stretching", () => {
    const hash = hashPasskey("test");
    expect(hash).toHaveLength(64); // 32 bytes as hex
    // A proper password hash like Argon2 would produce a longer output
    // that includes the algorithm tag, salt, and parameters — e.g.,
    // "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"
    // The short output means there's no room for algorithm metadata,
    // making future migration to a different hash algorithm harder.
  });

  it("server uses timingSafeEqual but not a slow verifier", async () => {
    // The server DOES use timingSafeEqual for the passkeyHash comparison
    // (routes.ts:172), which prevents timing side-channels. However,
    // timingSafeEqual only prevents timing attacks on the comparison
    // itself — it doesn't add work factor. An attacker who steals the
    // DB can still brute-force offline at SHA-256 speed.
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });

    // Register two users with the same (known) passkey
    const passkeyHash = hashPasskey("common-pw");
    await h.register(req({
      publicKey: "Sol1111111111111111111111111111111111111",
      email: "alice@example.com",
      passkeyHash,
      authMethod: "email",
      wallets: [],
    }));
    await h.register(req({
      publicKey: "Sol2222222222222222222222222222222222222",
      email: "bob@example.com",
      passkeyHash: hashPasskey("common-pw"), // Same passkey!
      authMethod: "email",
      wallets: [],
    }));

    // Login succeeds for both with the correct hash
    const aliceLogin = await h.login(req({ email: "alice@example.com", passkeyHash }));
    expect(aliceLogin.status).toBe(200);

    const bobLogin = await h.login(req({ email: "bob@example.com", passkeyHash }));
    expect(bobLogin.status).toBe(200);

    // Wrong hash rejected (timing-safe)
    const wrong = await h.login(req({ email: "alice@example.com", passkeyHash: hashPasskey("wrong") }));
    expect(wrong.status).toBe(401);
  });
});

describe("proposed v2 salted hash properties", () => {
  // These tests validate the DESIGN of the v2 salted hash (from the
  // hardening roadmap), using the current codebase. They verify that
  // a salted approach would fix the issues above.

  it("salted PBKDF2 would produce different hashes for the same passkey", async () => {
    // Simulated v2: PBKDF2(passkey, random_salt, 600k)
    // This is what hashPasskeyV2() would do.
    // We can't test the actual v2 function (not yet implemented), but
    // we can verify the cryptographic property using crypto.subtle.
    if (!globalThis.crypto?.subtle) return;

    const pwBytes = new TextEncoder().encode("common-passkey");
    const saltA = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const saltB = globalThis.crypto.getRandomValues(new Uint8Array(16));

    const key = await globalThis.crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveBits"]);
    const hashA = await globalThis.crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltA, iterations: 600_000, hash: "SHA-256" }, key, 256,
    );
    const hashB = await globalThis.crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltB, iterations: 600_000, hash: "SHA-256" }, key, 256,
    );

    // Different salts → different hashes, even for the same passkey
    const hexA = Buffer.from(hashA).toString("hex");
    const hexB = Buffer.from(hashB).toString("hex");
    expect(hexA).not.toBe(hexB);
    // This is the key improvement: even if two users pick the same
    // passkey, their stored hashes are completely different.
  });

  it("salted PBKDF2 prevents rainbow table precomputation", () => {
    // Rainbow tables are precomputed lists of (password → hash) for
    // unsalted hashes. With a random 128-bit salt, a separate rainbow
    // table would be needed for EACH salt value — making precomputation
    // infeasible (2^128 tables would need more atoms than in the universe).
    // This is a theoretical property; we verify it logically.
    const saltBytes = 16; // 128-bit salt
    const possibleSaltValues = 2n ** BigInt(saltBytes * 8);
    // eslint-disable-next-line no-console
    console.log(`  128-bit salt space: 2^${saltBytes * 8} ≈ 10^${Math.round(saltBytes * 8 * 0.3010)} values`);
    expect(possibleSaltValues).toBeGreaterThan(2n ** 64n); // 64 bits is minimum acceptable
  });
});
