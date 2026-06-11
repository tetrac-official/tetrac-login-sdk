// App-key derivation, secret encryption, hashing, and CSPRNG helpers.
// Key derivation + hashing use crypto-es; secret encryption uses Web Crypto AES-256-GCM.
//
// Cryptography notes:
//  (D1) RESOLVED — secret encryption is authenticated AES-256-GCM via Web Crypto (encryptSecret/
//       decryptSecret below); tampering throws on decrypt. Intentionally breaks byte-compat with the
//       legacy crypto-es AES-CBC format — no backward-compat path (old CBC blobs do not decrypt).
//  (D2) hashPasskey is an unsalted single SHA-256 (future hardening: salted slow verifier — Change 3).
//  (D3) deriveAppKeyFromPasskey defaults to 100k PBKDF2 (future: 600k — Change 2).
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

function appKeyToBytes(appKey: string): Uint8Array<ArrayBuffer> {
  // App key is 64 hex chars (256-bit, from PBKDF2 / SHA-256) -> 32 raw bytes. No 0x prefix.
  const out = new Uint8Array(new ArrayBuffer(appKey.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(appKey.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importAesGcmKey(appKey: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", appKeyToBytes(appKey), { name: "AES-GCM" }, false, usage);
}

/**
 * Encrypt a secret (e.g. hex private key) under the app key with AES-256-GCM.
 * Returns "${b64url(iv)}:${b64url(ciphertext+tag)}". Authenticated (AEAD).
 */
export async function encryptSecret(plaintext: string, appKey: string): Promise<string> {
  const key = await importAesGcmKey(appKey, ["encrypt"]);
  const iv = new Uint8Array(new ArrayBuffer(12));
  crypto.getRandomValues(iv); // 96-bit CSPRNG IV
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return `${b64urlEncode(iv)}:${b64urlEncode(new Uint8Array(ct))}`;
}

/** Decrypt a secret produced by encryptSecret. Throws on wrong key or tampering (GCM auth tag). */
export async function decryptSecret(ciphertext: string, appKey: string): Promise<string> {
  const parts = ciphertext.split(":");
  if (parts.length !== 2) throw new Error("Decryption failed: malformed ciphertext");
  const iv = b64urlDecode(parts[0]!);
  const ct = b64urlDecode(parts[1]!);
  const key = await importAesGcmKey(appKey, ["decrypt"]);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  }
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

/**
 * Constant-time comparison of two hex strings. Used server-side to compare
 * credential hashes without leaking timing about how many characters matched.
 * Does the full XOR-accumulate scan regardless of input; a length mismatch still
 * runs over the longer string and returns false. Pure, no Node 'crypto' needed.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
