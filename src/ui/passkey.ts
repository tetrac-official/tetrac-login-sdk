// src/ui/passkey.ts
//
// Self-contained CSPRNG passkey generator for the optional UI package. NO new
// runtime dependency (the `/ui` subpath stays dependency-light) — a small
// in-house base58 encoder replaces `bs58`. The output is an unambiguous,
// user-retypable secret: the Bitcoin base58 alphabet already omits 0 O I l.
//
// SECURITY / CRYPTO NOTES
// -----------------------
// * Randomness is WebCrypto's `crypto.getRandomValues` ONLY — never Math.random.
//   getRandomValues is a CSPRNG; Math.random is a non-cryptographic PRNG and MUST
//   NOT be used for a secret that encrypts an account vault.
// * Entropy is clamped to a MINIMUM of 16 bytes (128-bit). A caller asking for
//   fewer is silently raised to 16 — we never emit a sub-128-bit secret. A NaN /
//   non-finite / fractional request is floored/defaulted BEFORE allocation, so
//   `new Uint8Array(len)` can never silently truncate (12.9 -> length 12) or throw.
//   Default 24 bytes (~192-bit) -> ~32-33 base58 chars.
// * The encoder is a base-256 -> base-58 big-integer long-division. Because it
//   divides the full integer (not a per-byte `% 58`), it introduces NO modulo
//   bias: every input maps 1:1 to its canonical base58 string. Leading 0x00 bytes
//   map to leading '1's (the base58 zero digit), one '1' per leading zero byte.
// * This module holds no state and logs nothing. The generated string is returned
//   to the caller and is NEVER persisted, logged, or transmitted here.

/**
 * Bitcoin base58 alphabet. Deliberately omits the visually-ambiguous glyphs
 * 0 (zero), O (capital o), I (capital i) and l (lower L) by construction, so a
 * hand-copied passkey re-types unambiguously.
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Minimum entropy in bytes (128-bit). The generator clamps below this. */
export const MIN_PASSKEY_BYTES = 16;
/** Default entropy in bytes (~192-bit ≈ 32-33 base58 chars). */
export const DEFAULT_PASSKEY_BYTES = 24;

/**
 * Encode raw bytes to base58 (big-endian, Bitcoin alphabet). Each leading 0x00
 * byte maps to exactly one leading '1' (base58's zero digit), matching canonical
 * bs58 behaviour so length/round-tripping is predictable. Empty input -> "".
 */
export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Count leading zero bytes -> they become leading '1's, not part of the bignum.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Base-256 -> base-58 via repeated division on a byte-array "big integer".
  // `digits` holds the base-58 result, least-significant first.
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    // noUncheckedIndexedAccess widens indexed reads to `number | undefined`; the
    // index is provably in range here, so a narrowing cast keeps the math typed.
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8; // digit * 256 + carry
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  // Assemble: one '1' per leading zero byte, then the base-58 digits reversed
  // (most-significant first).
  let out = "";
  for (let i = 0; i < zeros; i++) out += BASE58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i] as number];
  return out;
}

/**
 * Sanitize a requested byte count to a safe integer, clamped to [16, ∞).
 * NaN / non-finite / ≤0 / fractional inputs all resolve to a valid ≥16 integer.
 */
function normalizeBytes(bytes: number): number {
  const n = Math.floor(Number(bytes));
  if (!Number.isFinite(n)) return DEFAULT_PASSKEY_BYTES; // NaN / ±Infinity -> default
  return Math.max(MIN_PASSKEY_BYTES, n); // hard 128-bit floor
}

/**
 * Generate a CSPRNG-strong, base58-encoded passkey. Uses WebCrypto's CSPRNG only
 * (never Math.random). Entropy is clamped to a 16-byte (128-bit) floor; the
 * default 24 bytes (192-bit) encodes to ~32-33 base58 chars.
 *
 * @param bytes desired entropy in bytes (default 24; clamped to a minimum of 16)
 */
export function generateStrongPasskey(bytes: number = DEFAULT_PASSKEY_BYTES): string {
  const len = normalizeBytes(bytes);
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf); // WebCrypto CSPRNG — never Math.random
  return encodeBase58(buf);
}
