import {
  deriveAppKeyFromPasskey,
  deriveAppKeyFromSignature,
  hashPasskey,
  encryptSecret,
  decryptSecret,
  randomHex,
  generateSessionToken,
} from "../src/core/crypto";

describe("key derivation", () => {
  it("derives a deterministic app key from passkey + email", () => {
    const a = deriveAppKeyFromPasskey("hunter2", "Alice@Example.com");
    const b = deriveAppKeyFromPasskey("hunter2", "alice@example.com  ");
    expect(a).toBe(b); // email is normalized (lowercase + trim)
    expect(a).toHaveLength(64); // 256-bit hex
  });

  it("changes the app key when the passkey changes", () => {
    expect(deriveAppKeyFromPasskey("a", "x@y.com")).not.toBe(
      deriveAppKeyFromPasskey("b", "x@y.com"),
    );
  });

  it("derives a deterministic app key from a signature", () => {
    const sig = "deadbeef".repeat(16);
    expect(deriveAppKeyFromSignature(sig)).toBe(deriveAppKeyFromSignature(sig));
    expect(deriveAppKeyFromSignature(sig)).toHaveLength(64);
  });

  it("hashes passkeys deterministically", () => {
    expect(hashPasskey("pw")).toBe(hashPasskey("pw"));
    expect(hashPasskey("pw")).not.toBe(hashPasskey("pw2"));
  });
});

describe("secret encryption", () => {
  it("round-trips a secret under the app key", async () => {
    const key = deriveAppKeyFromPasskey("pw", "a@b.com");
    const secret = "0x" + "11".repeat(32);
    const ct = await encryptSecret(secret, key);
    expect(ct).not.toContain(secret);
    expect(await decryptSecret(ct, key)).toBe(secret);
  });

  it("fails to decrypt with the wrong key", async () => {
    // AES-GCM keys are 32 raw bytes (64 hex), so use real derived keys here.
    const keyA = deriveAppKeyFromPasskey("a", "x@y.com");
    const keyB = deriveAppKeyFromPasskey("b", "x@y.com");
    const ct = await encryptSecret("topsecret", keyA);
    await expect(decryptSecret(ct, keyB)).rejects.toThrow();
  });
});

describe("CSPRNG", () => {
  it("produces unique hex of the right length", () => {
    expect(randomHex(32)).toHaveLength(64);
    expect(generateSessionToken()).not.toBe(generateSessionToken());
  });
});
