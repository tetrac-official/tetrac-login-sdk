// App-key derivation, secret encryption, hashing, and CSPRNG helpers.
// Uses crypto-es so blobs are byte-for-byte compatible with next-ttc.
import CryptoES from "crypto-es";

/**
 * Deterministically derive the 256-bit app (encryption) key for email/passkey
 * users: PBKDF2(passkey, salt = normalized email). Same inputs always yield the
 * same key, so wallets can be decrypted on any device without server storage.
 */
export function deriveAppKeyFromPasskey(
  passkey: string,
  email: string,
  iterations = 100_000,
): string {
  const salt = email.toLowerCase().trim();
  return CryptoES.PBKDF2(passkey, salt, {
    keySize: 256 / 32, // word count (32-bit words) -> 256-bit key
    iterations,
  }).toString(CryptoES.enc.Hex);
}

/**
 * Derive the app key for Web3 users from their wallet signature: SHA-256(sig).
 * Recoverable on any device by re-signing the same challenge message.
 */
export function deriveAppKeyFromSignature(signatureHex: string): string {
  return CryptoES.SHA256(signatureHex).toString(CryptoES.enc.Hex);
}

/** SHA-256 hash of the passkey, sent to the server for verification (never plaintext). */
export function hashPasskey(passkey: string): string {
  return CryptoES.SHA256(passkey).toString(CryptoES.enc.Hex);
}

/** Encrypt a secret (e.g. hex private key) under the app key. Returns ciphertext string. */
export function encryptSecret(plaintext: string, appKey: string): string {
  return CryptoES.AES.encrypt(plaintext, appKey).toString();
}

/** Decrypt a secret produced by encryptSecret. Throws if the key is wrong / blob is corrupt. */
export function decryptSecret(ciphertext: string, appKey: string): string {
  const out = CryptoES.AES.decrypt(ciphertext, appKey).toString(CryptoES.enc.Utf8);
  if (!out) throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  return out;
}

/** Cryptographically-secure random hex string, edge- and Node-safe. */
export function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  const webcrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (!webcrypto?.getRandomValues) {
    throw new Error("No secure RNG available (globalThis.crypto.getRandomValues missing)");
  }
  webcrypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Generate an opaque 256-bit session token (64 hex chars). */
export function generateSessionToken(): string {
  return randomHex(32);
}

/** Generate a 256-bit wallet-login challenge (64 hex chars). */
export function generateChallenge(): string {
  return randomHex(32);
}
