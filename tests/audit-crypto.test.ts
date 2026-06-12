// CHARACTERIZATION TESTS for the cryptography findings from
// audits/opus-4.8-comprehensive-audit.md. The hardening has landed, so these now
// assert the RESOLVED behavior (the original vulnerable asserts were inverted).
//
// Findings covered: C1 (unsalted SHA-256 passkeyHash → signature auth), H1 (AES-CBC
// → authenticated AES-256-GCM), H2 (email salt + 100k → 600k + domain-separated
// SHA-256(appId:email) salt), H4 (domain-unbound key message → appId-bound message),
// CRYPTO-5 (timingSafeEqual is correct — confirms the "disproven" reconciliation).
import { createHash } from "crypto";
import CryptoES from "crypto-es";
import {
  deriveAppKeyFromPasskey,
  deriveAppKeyFromSignature,
  encryptSecret,
  decryptSecret,
  timingSafeEqual,
} from "../src/core/crypto";
import { deriveAuthPublicKey } from "../src/client/authKey";
import { DEFAULT_CONFIG, PBKDF2_ITERATIONS } from "../src/core/config";
import { WALLET_APP_KEY_MESSAGE, walletAppKeyMessage } from "../src/core/index";

const sha256hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const ORIGINAL = "0x" + "11".repeat(32);

describe("C1 RESOLVED — no passkey hash on the server (signature auth)", () => {
  it("the stored credential is an ed25519 auth public key derived from (not equal to) the appKey", () => {
    // The unsalted-SHA-256 passkeyHash was removed in v0.2.1 Change 3. Email/biometric
    // accounts now authenticate by signing a challenge with a derived auth keypair; the
    // server stores only this public key — there is no fast hash to GPU-crack offline.
    const appKey = deriveAppKeyFromPasskey("letmein", "victim@example.com");
    const authPub = deriveAuthPublicKey(appKey);
    expect(authPub).toMatch(/^[0-9a-f]{64}$/); // 32-byte ed25519 public key (hex)
    expect(authPub).not.toBe(appKey); // domain-separated from the wallet-encryption key
  });
});

describe("H2 RESOLVED — 600k iterations + domain-separated salt (no longer the bare email)", () => {
  it("default security level is 2 = 600k, meeting OWASP 2023", () => {
    expect(DEFAULT_CONFIG.securityLevel).toBe(2);
    expect(PBKDF2_ITERATIONS[DEFAULT_CONFIG.securityLevel]).toBeGreaterThanOrEqual(600_000);
  });

  it("the salt is SHA-256(appId : email), NOT the bare email", () => {
    // Old (vulnerable) behavior used the bare normalized email as the salt:
    const bareEmailSalt = CryptoES.PBKDF2("pw", "a@b.com", { keySize: 256 / 32, iterations: 100_000 })
      .toString(CryptoES.enc.Hex);
    expect(deriveAppKeyFromPasskey("pw", "A@B.com  ", 100_000, "ttc")).not.toBe(bareEmailSalt);

    // …it now matches a derivation whose salt is SHA-256("ttc:a@b.com"):
    const domainSalt = CryptoES.SHA256("ttc:a@b.com");
    const expected = CryptoES.PBKDF2("pw", domainSalt, { keySize: 256 / 32, iterations: 100_000 })
      .toString(CryptoES.enc.Hex);
    expect(deriveAppKeyFromPasskey("pw", "A@B.com  ", 100_000, "ttc")).toBe(expected);
  });

  it("domain separation: a different appId ⇒ a different key; same appId+inputs ⇒ same key", () => {
    expect(deriveAppKeyFromPasskey("pw", "u@x.com", 100_000, "appA")).not.toBe(
      deriveAppKeyFromPasskey("pw", "u@x.com", 100_000, "appB"),
    );
    expect(deriveAppKeyFromPasskey("pw", "u@x.com", 100_000, "appA")).toBe(
      deriveAppKeyFromPasskey("pw", "u@x.com", 100_000, "appA"),
    );
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

describe("H4 RESOLVED — the wallet-app-key message is domain-bound by appId", () => {
  it("the signed message embeds appId, so different apps sign DIFFERENT messages", () => {
    expect(walletAppKeyMessage("appA")).not.toBe(walletAppKeyMessage("appB"));
    expect(walletAppKeyMessage("myapp")).toContain("myapp");
    expect(walletAppKeyMessage("appA").startsWith(WALLET_APP_KEY_MESSAGE)).toBe(true); // built on the base text
  });

  it("same appId ⇒ same message (deterministic — recovery/login stays stable)", () => {
    expect(walletAppKeyMessage("appA")).toBe(walletAppKeyMessage("appA"));
  });

  it("isolation comes from the MESSAGE, not the hash: deriveAppKeyFromSignature stays pure", () => {
    // Two apps no longer share a key because the wallet signs DIFFERENT messages
    // (different appId) → different signatures → different keys. The hash step itself
    // is intentionally origin-free, so identical signatures still map to one key.
    const sig = "deadbeef".repeat(16);
    expect(deriveAppKeyFromSignature(sig)).toBe(deriveAppKeyFromSignature(sig));
    expect(walletAppKeyMessage("appA")).not.toBe(walletAppKeyMessage("appB"));
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
