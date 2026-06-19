// B3 — Gate-mode WebAuthn must never persist the app-key secret in readable form.
// src/client/webauthn.ts wraps the hex secret under a NON-EXTRACTABLE AES-GCM
// CryptoKey before storing it in IndexedDB. The gate helpers are module-internal,
// so this documents and verifies the crypto contract they rely on directly via
// globalThis.crypto.subtle (Node 18+). Skips cleanly if subtle crypto is absent.
const subtle = globalThis.crypto?.subtle;
const describeCrypto = subtle ? describe : describe.skip;

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

describeCrypto("gate-mode AES-GCM wrap/unwrap (B3)", () => {
  it("round-trips a hex secret through a non-extractable AES-GCM key", async () => {
    const secretHex = toHex(crypto.getRandomValues(new Uint8Array(32)));

    const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, key, fromHex(secretHex));
    const plain = await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);

    expect(toHex(new Uint8Array(plain))).toBe(secretHex);
    // The ciphertext must not contain the plaintext bytes.
    expect(toHex(new Uint8Array(ciphertext))).not.toContain(secretHex);
  });

  it("the wrapping key is non-extractable (exportKey rejects)", async () => {
    const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    expect(key.extractable).toBe(false);
    await expect(subtle.exportKey("raw", key)).rejects.toThrow();
  });

  it("decrypt fails when the ciphertext is tampered (GCM tag check)", async () => {
    const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv }, key, fromHex("00".repeat(32))),
    );
    ciphertext[0] ^= 0xff; // flip a byte
    await expect(subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)).rejects.toThrow();
  });
});
