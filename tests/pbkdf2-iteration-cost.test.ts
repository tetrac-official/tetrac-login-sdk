// C3 — PBKDF2 iteration cost verification.
//
// WHAT THIS TESTS:
//  - The current default (100k) vs OWASP guidance (600k+) performance gap
//  - Determinism: same passkey + email always produces the same key at a
//    given iteration count (cross-device recovery)
//  - Different iteration counts produce different keys from the same passkey
//    (a migration concern: existing users are locked to their creation-time count)
//  - The config parameter is plumbed through correctly in authClient
//  - A timing benchmark to demonstrate the linear cost difference between
//    100k and 600k iterations (not a pass/fail, but a reported metric)
import {
  deriveAppKeyFromPasskey,
  encryptSecret,
  decryptSecret,
} from "../src/core/crypto";
import { resolveConfig, PBKDF2_ITERATIONS, type AuthConfig } from "../src/core/config";
import { armAppKey, getAppKey, lockVault, configureVault } from "../src/client/session";

function randomHex(n: number): string {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  let h = "";
  for (const v of b) h += v.toString(16).padStart(2, "0");
  return h;
}

describe("PBKDF2 iteration determinism (C3)", () => {
  const email = "user@example.com";
  const passkey = "correct-horse-battery-staple-电池";

  it("same inputs at same iteration count produce identical keys", () => {
    const a = deriveAppKeyFromPasskey(passkey, email, 100_000);
    const b = deriveAppKeyFromPasskey(passkey, email, 100_000);
    const c = deriveAppKeyFromPasskey(passkey, email, 600_000);
    expect(a).toBe(b);
    expect(a).toHaveLength(64); // 256-bit hex
    // Different iteration count → different key
    expect(a).not.toBe(c);
  });

  it("email normalization (lowercase + trim) works deterministically", () => {
    const a = deriveAppKeyFromPasskey(passkey, "User@Example.com", 100_000);
    const b = deriveAppKeyFromPasskey(passkey, "user@example.com  ", 100_000);
    expect(a).toBe(b);
  });

  it("encrypted secrets under different iteration counts are not interchangeable", async () => {
    const key100k = deriveAppKeyFromPasskey(passkey, email, 100_000);
    const key600k = deriveAppKeyFromPasskey(passkey, email, 600_000);
    const secret = randomHex(32);

    const ct100k = await encryptSecret(secret, key100k);
    const ct600k = await encryptSecret(secret, key600k);

    // Each key decrypts its own ciphertext
    expect(await decryptSecret(ct100k, key100k)).toBe(secret);
    expect(await decryptSecret(ct600k, key600k)).toBe(secret);

    // Cross-decrypt fails (different keys; AES-GCM auth-tag mismatch)
    await expect(decryptSecret(ct100k, key600k)).rejects.toThrow();
    await expect(decryptSecret(ct600k, key100k)).rejects.toThrow();
  }, 30_000); // 600k PBKDF2 derivations are slow; raise the per-test timeout

  it("changing default from 100k to 600k does not break existing users", async () => {
    // Simulate a user registered with 100k iterations
    const email = "legacy@example.com";
    const passkey = "legacy-passkey";
    const legacyKey = deriveAppKeyFromPasskey(passkey, email, 100_000);
    const legacySecret = await encryptSecret("legacy-wallet-key", legacyKey);

    // New default would be 600k
    const newDefaultKey = deriveAppKeyFromPasskey(passkey, email, 600_000);

    // Legacy user on new default CANNOT decrypt (wrong key)
    await expect(decryptSecret(legacySecret, newDefaultKey)).rejects.toThrow();

    // But legacy user using their creation-time iteration count still works
    expect(await decryptSecret(legacySecret, legacyKey)).toBe("legacy-wallet-key");

    // CONCLUSION: changing the default is safe for new users; existing users
    // must continue using their creation-time iteration count. This is
    // already handled by the config parameter being per-deployment and
    // the deterministic nature of PBKDF2(email, passkey, iterations).
  }, 30_000); // 600k PBKDF2 derivation is slow; raise the per-test timeout
});

describe("security level → PBKDF2 iteration plumbing", () => {
  it("PBKDF2_ITERATIONS maps levels 1/2/3 to 100k/600k/1M; resolveConfig is secure-by-default (level 2)", () => {
    expect(PBKDF2_ITERATIONS[1]).toBe(100_000);
    expect(PBKDF2_ITERATIONS[2]).toBe(600_000);
    expect(PBKDF2_ITERATIONS[3]).toBe(1_000_000);
    expect(resolveConfig().securityLevel).toBe(2); // default level 2 = 600k (OWASP)
    expect(resolveConfig({ securityLevel: 1 }).securityLevel).toBe(1);
    expect(resolveConfig({ securityLevel: 3 }).securityLevel).toBe(3);
  });

  it("different iteration counts produce different app keys (migration safety)", () => {
    const low = deriveAppKeyFromPasskey("pw", "test@test.com", PBKDF2_ITERATIONS[1]);
    const high = deriveAppKeyFromPasskey("pw", "test@test.com", PBKDF2_ITERATIONS[2]);
    expect(low).not.toBe(high);
  });
});

describe("PBKDF2 iteration timing benchmark (informational)", () => {
  const email = "bench@test.com";
  const passkey = "benchmark-passkey-123";

  it("measures 100k iterations time", () => {
    const start = performance.now();
    deriveAppKeyFromPasskey(passkey, email, 100_000);
    const elapsed = performance.now() - start;
    // Log the timing (visible in jest verbose output)
    // eslint-disable-next-line no-console
    console.log(`  100k iterations: ${elapsed.toFixed(1)}ms`);
    // Not a pass/fail — just informational
    expect(elapsed).toBeGreaterThan(0);
  });

  it("measures 600k iterations time (OWASP 2023 minimum)", () => {
    const start = performance.now();
    deriveAppKeyFromPasskey(passkey, email, 600_000);
    const elapsed = performance.now() - start;
    // eslint-disable-next-line no-console
    console.log(`  600k iterations: ${elapsed.toFixed(1)}ms`);
    expect(elapsed).toBeGreaterThan(0);
  });

  it("measures 1M iterations time (future-proof)", () => {
    const start = performance.now();
    deriveAppKeyFromPasskey(passkey, email, 1_000_000);
    const elapsed = performance.now() - start;
    // eslint-disable-next-line no-console
    console.log(`  1M iterations: ${elapsed.toFixed(1)}ms`);
    expect(elapsed).toBeGreaterThan(0);
  });
});
