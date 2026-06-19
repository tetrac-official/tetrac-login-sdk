// App-key derivation, secret encryption, hashing, and CSPRNG helpers.
// Key derivation + hashing use @noble/hashes (sync, audited); secret encryption
// uses Web Crypto AES-256-GCM (encryptSecret/decryptSecret). No crypto-es.
//
// Cryptography notes:
//  (D1) Secret encryption is authenticated AES-256-GCM via Web Crypto; tampering
//       throws on decrypt. Ciphertext is "iv:ct+tag" (b64url) — no legacy CBC compat.
//  (D2) The PBKDF2 iteration count comes from config.securityLevel (default 600k),
//       is pinned per-user, and is passed in to deriveAppKeyFromPasskey.
import { sha256 } from "@noble/hashes/sha2.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";

/**
 * Deterministically derive the 256-bit app (encryption) key for email/passkey
 * users: PBKDF2(passkey, salt = SHA-256(appId : normalized email)). Same inputs
 * always yield the same key, so wallets decrypt on any device without server
 * storage. The `appId` DOMAIN-SEPARATES the salt (CRYPTO-2): the same (passkey,
 * email) derives a DIFFERENT key per deployment, so a key cracked/coerced on one
 * app can't unlock the same user on another, and a precomputed table is per-appId.
 * Default "ttc" must match DEFAULT_CONFIG.appId; override per deployment.
 */
export function deriveAppKeyFromPasskey(
  passkey: string,
  email: string,
  iterations = 100_000,
  appId = "ttc",
): string {
  // SHA-256(appId : email) → a fixed-length, domain-separated, per-user salt.
  const salt = sha256(utf8ToBytes(`${appId}:${email.toLowerCase().trim()}`));
  // PBKDF2-HMAC-SHA256 → 32-byte (256-bit) derived key, hex-encoded.
  return bytesToHex(pbkdf2(sha256, utf8ToBytes(passkey), salt, { c: iterations, dkLen: 32 }));
}

/**
 * Derive the app key for Web3 users from their wallet signature: SHA-256(sig).
 * Recoverable on any device by re-signing the same challenge message.
 */
export function deriveAppKeyFromSignature(signatureHex: string): string {
  return bytesToHex(sha256(utf8ToBytes(signatureHex)));
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

/**
 * SHA-256 (hex) of a request User-Agent, for the optional coarse session→UA binding
 * (config.bindSessionToUserAgent). Returns undefined for a missing/empty UA so the
 * caller skips binding rather than pinning the session to the empty string.
 */
export function hashUserAgent(userAgent: string | null | undefined): string | undefined {
  if (!userAgent) return undefined;
  return bytesToHex(sha256(utf8ToBytes(userAgent)));
}

/** Generate a 256-bit wallet-login challenge (64 hex chars). */
export function generateChallenge(): string {
  return randomHex(32);
}

/**
 * Constant-time comparison of two hex strings. Used server-side to compare
 * credential hashes without leaking timing about how many characters matched.
 * Folds the length difference into `diff` up front and scans the full max-length
 * window, substituting 0 past the end of the shorter string so it never indexes
 * out of bounds (avoids relying on charCodeAt→NaN propagation, audit F8). A length
 * mismatch returns false. Pure, no Node 'crypto' needed.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const la = a.length;
  const lb = b.length;
  const len = Math.max(la, lb);
  let diff = la ^ lb; // non-zero iff the lengths differ
  for (let i = 0; i < len; i++) {
    const ca = i < la ? a.charCodeAt(i) : 0;
    const cb = i < lb ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}
