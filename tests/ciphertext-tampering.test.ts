// C1/H1 — wallet-secret encryption is authenticated (AES-256-GCM via Web Crypto).
// Proves the integrity property the old crypto-es AES-CBC lacked: any tampering
// (ciphertext bitflip, IV change, truncation) or a wrong key throws on decrypt.
// (Previously this file documented the CBC weakness; v0.2.1 Change 1 fixed it by
// replacing crypto-es AES-CBC with Web Crypto AES-256-GCM in encryptSecret/decryptSecret.)
import { encryptSecret, decryptSecret, deriveAppKeyFromPasskey } from "../src/core/crypto";

const subtle = globalThis.crypto?.subtle;
const describeGcm = subtle ? describe : describe.skip;

function randomHex(n: number): string {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  let h = "";
  for (const v of b) h += v.toString(16).padStart(2, "0");
  return h;
}

describeGcm("wallet-secret encryption — AES-256-GCM integrity (C1/H1)", () => {
  const key = deriveAppKeyFromPasskey("test-passkey", "a@b.com");
  const secret = "0x" + randomHex(32); // simulated EVM private key

  it("round-trips a secret with the right key", async () => {
    const ct = await encryptSecret(secret, key);
    expect(ct).not.toContain(secret);
    expect(ct.split(":")).toHaveLength(2); // "b64url(iv):b64url(ciphertext+tag)"
    expect(await decryptSecret(ct, key)).toBe(secret);
  });

  it("rejects a wrong key (GCM auth-tag mismatch)", async () => {
    const ct = await encryptSecret(secret, key);
    const wrongKey = deriveAppKeyFromPasskey("test-passkey", "different@b.com");
    await expect(decryptSecret(ct, wrongKey)).rejects.toThrow();
  });

  it("rejects ANY single-character tamper in the ciphertext (no silent garbage)", async () => {
    const ct = await encryptSecret(secret, key);
    const [iv, body] = ct.split(":");
    for (let i = 0; i < body!.length; i += 3) {
      const flipped = body![i] === "A" ? "B" : "A";
      const bad = `${iv}:${body!.slice(0, i)}${flipped}${body!.slice(i + 1)}`;
      await expect(decryptSecret(bad, key)).rejects.toThrow();
    }
  });

  it("rejects IV tampering", async () => {
    const ct = await encryptSecret(secret, key);
    const [iv, body] = ct.split(":");
    const flipped = iv![0] === "A" ? "B" : "A";
    await expect(decryptSecret(`${flipped}${iv!.slice(1)}:${body}`, key)).rejects.toThrow();
  });

  it("rejects truncated ciphertext", async () => {
    const ct = await encryptSecret(secret, key);
    await expect(decryptSecret(ct.slice(0, -4), key)).rejects.toThrow();
  });

  it("rejects malformed (no delimiter) input", async () => {
    await expect(decryptSecret("not-a-valid-blob", key)).rejects.toThrow(/malformed/i);
  });
});
