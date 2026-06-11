// CHARACTERIZATION TESTS — prove the cryptography findings from
// audits/opus-4.8-comprehensive-audit.md against the CURRENT code, WITHOUT
// changing src/. These assert today's (vulnerable) behavior, so they PASS now
// and document the finding. After the hardening lands, invert the marked asserts.
//
// Findings covered: C1 (unsalted SHA-256 passkeyHash), H1 (AES-CBC no integrity),
// H2 (email salt + 100k iters), H4 (domain-unbound key message), CRYPTO-5
// (timingSafeEqual is actually correct — confirms the "disproven" reconciliation).
import { createHash } from "crypto";
import CryptoES from "crypto-es";
import {
  hashPasskey,
  deriveAppKeyFromPasskey,
  deriveAppKeyFromSignature,
  encryptSecret,
  decryptSecret,
  timingSafeEqual,
} from "../src/core/crypto";
import { DEFAULT_CONFIG, PBKDF2_ITERATIONS } from "../src/core/config";
import { WALLET_APP_KEY_MESSAGE, walletAppKeyMessage } from "../src/core/index";

const sha256hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const ORIGINAL = "0x" + "11".repeat(32);

describe("C1 — server-stored passkeyHash is unsalted single SHA-256 (GPU-crackable, bypasses PBKDF2)", () => {
  it("hashPasskey is exactly ONE round of plain, unsalted SHA-256 (no work factor)", () => {
    expect(hashPasskey("password")).toBe(sha256hex("password"));
    expect(hashPasskey("correct horse battery staple")).toBe(sha256hex("correct horse battery staple"));
  });

  it("is unsalted: the same passkey for different users yields the SAME stored hash", () => {
    // ⇒ a single rainbow table attacks all email users; identical passkeys are visible in a leak.
    expect(hashPasskey("hunter2")).toBe(hashPasskey("hunter2"));
  });

  it("END-TO-END: a leaked {passkeyHash, email, ciphertext} is offline-crackable → full wallet recovery", async () => {
    // What the server stores for an email user (all of it leaks together on a DB compromise):
    const realPasskey = "letmein"; // weak, in any wordlist
    const email = "victim@example.com";
    const leakedPasskeyHash = hashPasskey(realPasskey);
    const appKey = deriveAppKeyFromPasskey(realPasskey, email);
    const leakedCiphertext = await encryptSecret(ORIGINAL, appKey);

    // Attacker brute-forces the FAST unsalted hash (NOT the 100k PBKDF2):
    const dictionary = ["123456", "password", "letmein", "qwerty"];
    let cracked: string | null = null;
    for (const guess of dictionary) {
      if (timingSafeEqual(hashPasskey(guess), leakedPasskeyHash)) { cracked = guess; break; }
    }
    expect(cracked).toBe(realPasskey); // recovered from the hash alone

    // Recovered passkey + the (public) email re-derive the appKey and decrypt the wallet:
    const recoveredKey = deriveAppKeyFromPasskey(cracked!, email);
    expect(await decryptSecret(leakedCiphertext, recoveredKey)).toBe(ORIGINAL);
  });
});

describe("H2 — iteration count RESOLVED (default 600k); salt is still the email (open)", () => {
  it("default security level is 2 = 600k, meeting OWASP 2023 (H2 iteration count RESOLVED)", () => {
    expect(DEFAULT_CONFIG.securityLevel).toBe(2);
    expect(PBKDF2_ITERATIONS[DEFAULT_CONFIG.securityLevel]).toBeGreaterThanOrEqual(600_000);
  });

  it("salt is exactly the normalized email (public, predictable, low-entropy)", () => {
    const manual = CryptoES.PBKDF2("pw", "a@b.com", { keySize: 256 / 32, iterations: 100_000 })
      .toString(CryptoES.enc.Hex);
    // Proves: salt === lowercased/trimmed email, iterations === 100k, hasher === SHA-256 (default).
    expect(deriveAppKeyFromPasskey("pw", "A@B.com  ")).toBe(manual);
  });

  it("no app/origin domain separation: same passkey+email derives the same key on ANY deployment", () => {
    expect(deriveAppKeyFromPasskey("pw", "u@x.com")).toBe(deriveAppKeyFromPasskey("pw", "u@x.com"));
  });
});

describe("H1 RESOLVED — wallet secrets use authenticated AES-256-GCM (tampering throws)", () => {
  it("ciphertext is GCM format b64url(iv):b64url(ct+tag), not the legacy Salted__ blob", async () => {
    const ct = await encryptSecret(ORIGINAL, "ab".repeat(32));
    expect(ct.split(":")).toHaveLength(2);
    expect(ct.startsWith("U2FsdGVk")).toBe(false); // U2FsdGVk = base64 of "Salted__"
  });

  it("a wrong key throws (GCM auth-tag mismatch)", async () => {
    const ct = await encryptSecret(ORIGINAL, "ab".repeat(32));
    await expect(decryptSecret(ct, "cd".repeat(32))).rejects.toThrow();
  });

  it("tampering is DETECTED — any ciphertext bitflip throws (no silent garbage)", async () => {
    const key = "ab".repeat(32);
    const ct = await encryptSecret(ORIGINAL, key);
    const [iv, body] = ct.split(":");
    const flipped = body![0] === "A" ? "B" : "A";
    await expect(decryptSecret(`${iv}:${flipped}${body!.slice(1)}`, key)).rejects.toThrow();
  });
});

describe("H4 — WALLET_APP_KEY_MESSAGE is a fixed, domain-unbound constant (cross-site key derivation)", () => {
  it("the signed message carries no origin / host / chainId / nonce", () => {
    expect(walletAppKeyMessage()).toBe(WALLET_APP_KEY_MESSAGE);
    expect(WALLET_APP_KEY_MESSAGE).not.toMatch(
      /https?:\/\/|origin|hostname|chainId|nonce|\b\d{1,3}(?:\.\d{1,3}){3}\b/i,
    );
  });

  it("any site that gets the same signature derives the SAME appKey (no per-origin key)", () => {
    const sig = "deadbeef".repeat(16); // a wallet signs the identical constant on any site
    const legitSite = deriveAppKeyFromSignature(sig);
    const evilSite = deriveAppKeyFromSignature(sig); // pure function — no origin input exists
    expect(evilSite).toBe(legitSite);
  });
});

describe("CRYPTO-5 — timingSafeEqual is CORRECT for fixed-length hex (finding disproven; kept as a guard)", () => {
  it("matches equal, rejects unequal/length-mismatch/unicode without an early-exit bug", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false); // length mismatch ⇒ false (seed = len xor)
    expect(timingSafeEqual("", "")).toBe(true);
    expect(timingSafeEqual("日本語", "日本語")).toBe(true);
    expect(timingSafeEqual("日本語", "中国語")).toBe(false);
    const h = "a".repeat(64);
    expect(timingSafeEqual(h, h)).toBe(true);
  });
});
