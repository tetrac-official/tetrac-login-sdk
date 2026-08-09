// H-3 — the secret that encrypts every wallet had no strength floor.
//
// `deriveAppKeyFromPasskey` took any string straight into PBKDF2, and the shipped UI's
// submit button was guarded only by `!passkey`, so any non-empty value was accepted. An
// attacker with database read access (leaked backup, replica, world-readable Supabase
// `public` schema) gets the ciphertext, the email, and the pinned iteration count — the
// email and appId fully determine the salt — and brute-forces offline, with AES-GCM's auth
// tag as an exact oracle. Against a human-chosen password, 600k iterations buys hours.
//
// The floor is LENGTH ONLY. No composition rule: `P@ssw0rd!` satisfies every
// upper/digit/symbol regex and is in every cracking wordlist, while a long passphrase fails
// most of them despite being far stronger — which is why NIST SP 800-63B dropped them.
//
// 🚨 The critical boundary: registration enforces it, LOGIN MUST NOT. An account created
// before the floor holds a shorter passkey, and refusing to derive for it would strand
// wallets that nothing else can decrypt — strictly worse than the weak key.
import { checkPasskeyLength, MIN_PASSKEY_LENGTH, deriveAppKeyFromPasskey } from "../src/core/crypto";
import { generateStrongPasskey, DEFAULT_PASSKEY_BYTES } from "../src/ui/passkey";

describe("H-3 — the length floor itself", () => {
  it("🚨 rejects anything shorter than the floor", () => {
    for (const weak of ["", "a", "hunter2", "password", "correct-horse"]) {
      expect(checkPasskeyLength(weak)).toBeTruthy();
    }
  });

  it("accepts the floor exactly, and anything longer", () => {
    expect(checkPasskeyLength("a".repeat(MIN_PASSKEY_LENGTH))).toBeNull();
    expect(checkPasskeyLength("a".repeat(MIN_PASSKEY_LENGTH + 1))).toBeNull();
  });

  it("the message says WHY, not just what", () => {
    // A bare "too short" invites the user to pad it by one character. The reason this
    // secret is different — unresettable, unrecoverable — is the part that changes behaviour.
    const msg = checkPasskeyLength("short")!;
    expect(msg).toMatch(new RegExp(`${MIN_PASSKEY_LENGTH}`));
    expect(msg).toMatch(/cannot be reset|recover/i);
  });

  it("🚨 imposes NO composition rule", () => {
    // Length is the only axis. A long all-lowercase passphrase must pass; a short one
    // bristling with symbols and digits must not. Enforcing the opposite is the classic
    // mistake this finding's fix deliberately avoids.
    expect(checkPasskeyLength("correcthorsebatterystaple")).toBeNull();
    expect(checkPasskeyLength("P@ssw0rd!")).toBeTruthy();
  });

  it("the generated default clears the floor with enormous margin", () => {
    // ~192 bits, ~32-33 base58 chars. The floor is a backstop for the user who overrides
    // the generator; the generator is the actual control.
    for (let i = 0; i < 20; i++) {
      const pk = generateStrongPasskey(DEFAULT_PASSKEY_BYTES);
      expect(checkPasskeyLength(pk)).toBeNull();
      expect(pk.length).toBeGreaterThan(MIN_PASSKEY_LENGTH);
    }
  });

  it("even the generator's minimum entropy clears the floor", () => {
    // generateStrongPasskey clamps to a 128-bit floor; that must not encode shorter than
    // the character floor, or the two controls would contradict each other.
    for (let i = 0; i < 20; i++) {
      expect(checkPasskeyLength(generateStrongPasskey(16))).toBeNull();
    }
  });
});

describe("H-3 — derivation is NOT gated (existing accounts keep their wallets)", () => {
  it("🚨 deriveAppKeyFromPasskey still accepts a short passkey", () => {
    // The single most important case in this file. Someone registered with "hunter2" before
    // the floor existed; their wallets are encrypted under the key it derives. Throwing here
    // would lock them out permanently — a worse outcome than the weak key they already have.
    expect(() => deriveAppKeyFromPasskey("hunter2", "old@example.com", 100_000, "app")).not.toThrow();
  });

  it("🚨 a short passkey still derives the SAME key it always did", () => {
    // Not merely "doesn't throw" — the value must be unchanged, or the wallets are gone
    // regardless of whether an exception was raised.
    const a = deriveAppKeyFromPasskey("hunter2", "old@example.com", 100_000, "app");
    const b = deriveAppKeyFromPasskey("hunter2", "old@example.com", 100_000, "app");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});
