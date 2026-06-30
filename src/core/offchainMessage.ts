// Solana off-chain message (v0) envelope encoder — shared by the client Ledger
// signer (to build what the device signs) AND the server verifier (to
// reconstruct the same preimage and accept a hardware-wallet login signature).
// Lives in /core because it is pure, framework-agnostic byte work (no DOM, no
// React, no @ledgerhq) used on both sides of the wire.
//
// It builds the exact byte preimage the Ledger Solana app parses and signs in
// `signOffchainMessage` (INS 0x07). The layout is fixed by the device firmware
// (`parse_offchain_message_header`), NOT by hw-app-solana — that library only
// prepends the derivation path and chunks the buffer, so the caller MUST supply
// the fully-formed envelope. The result is a standards-compliant Solana
// off-chain message signature (same preimage as `solana sign-offchain-message`),
// which verifies against this envelope — NOT against the raw message bytes.
//
// V0 single-signer layout (header = 85 bytes, then the message):
//   signing domain   16 bytes  0xFF "solana offchain"
//   header version    1 byte   0x00
//   application domain 32 bytes (all-zero = "no domain"; safe default)
//   message format    1 byte   0 = RestrictedAscii, 1 = LimitedUtf8
//   signer count      1 byte   0x01
//   signer pubkey    32 bytes  the signing account (device checks it matches the path)
//   message length    2 bytes  u16 little-endian (must equal the real length, != 0)
//   message          <length> bytes
//
// Uint8Array-only: the SDK never relies on a global `Buffer`, which is not
// reliably present in Next.js App Router client components.

const SIGNING_DOMAIN: Uint8Array = (() => {
  const tail = new TextEncoder().encode("solana offchain"); // 15 bytes
  const domain = new Uint8Array(16);
  domain[0] = 0xff;
  domain.set(tail, 1);
  return domain;
})();

const APPLICATION_DOMAIN_LEN = 32;
const HEADER_VERSION_V0 = 0x00;
const FORMAT_RESTRICTED_ASCII = 0x00;
const FORMAT_LIMITED_UTF8 = 0x01;
/** Conservative body cap that signs without forcing Blind Signing across deployed app versions. */
const DEFAULT_MAX_MESSAGE_BYTES = 1212;

export interface EncodeOffchainMessageOptions {
  /** 32-byte application domain. Defaults to all-zero ("no domain"). */
  applicationDomain?: Uint8Array;
  /**
   * Allow a non-ASCII but valid UTF-8 message (format = LimitedUtf8). The device
   * cannot render these, so signing REQUIRES the user to enable Blind Signing in
   * the Solana app. Defaults to false (ASCII-only, no blind signing needed).
   */
  allowUtf8?: boolean;
  /** Override the on-device length cap (default 1212 bytes). */
  maxMessageBytes?: number;
}

/** Printable ASCII (0x20–0x7e) plus newline (0x0a) — what the V0 RestrictedAscii format allows. */
function isPrintableAscii(bytes: Uint8Array): boolean {
  for (const c of bytes) {
    if (c === 0x0a) continue;
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/**
 * Build the V0 off-chain message envelope the Ledger Solana app validates and
 * signs. `signerPublicKey` must be the 32-byte ed25519 key of the signing
 * account (the device rejects the request if it doesn't match the path).
 *
 * @throws if the pubkey isn't 32 bytes, the message is empty/too long, or the
 *         message isn't ASCII (unless `allowUtf8` is set).
 */
export function encodeOffchainMessage(
  message: Uint8Array | string,
  signerPublicKey: Uint8Array,
  options: EncodeOffchainMessageOptions = {},
): Uint8Array {
  const msg = typeof message === "string" ? new TextEncoder().encode(message) : message;

  if (signerPublicKey.length !== 32) {
    throw new Error(
      `Ledger off-chain message: signer public key must be 32 bytes (got ${signerPublicKey.length}).`,
    );
  }
  if (msg.length === 0) {
    throw new Error("Ledger off-chain message: message must be non-empty.");
  }
  const maxLen = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  if (msg.length > maxLen) {
    throw new Error(
      `Ledger off-chain message: ${msg.length} bytes exceeds the ${maxLen}-byte on-device limit.`,
    );
  }

  let format: number;
  if (isPrintableAscii(msg)) {
    format = FORMAT_RESTRICTED_ASCII;
  } else if (options.allowUtf8) {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(msg);
    } catch {
      throw new Error("Ledger off-chain message: message is not valid UTF-8.");
    }
    format = FORMAT_LIMITED_UTF8;
  } else {
    throw new Error(
      "Ledger off-chain message: only printable ASCII (and newlines) are supported by default. Pass { allowUtf8: true } to sign UTF-8 (the device then requires Blind Signing).",
    );
  }

  const appDomain = options.applicationDomain ?? new Uint8Array(APPLICATION_DOMAIN_LEN);
  if (appDomain.length !== APPLICATION_DOMAIN_LEN) {
    throw new Error(`Ledger off-chain message: applicationDomain must be ${APPLICATION_DOMAIN_LEN} bytes.`);
  }

  // 16 + 1 + 32 + 1 + 1 + 32 + 2 = 85-byte header, then the message body.
  const out = new Uint8Array(85 + msg.length);
  let o = 0;
  out.set(SIGNING_DOMAIN, o);
  o += SIGNING_DOMAIN.length;
  out[o++] = HEADER_VERSION_V0;
  out.set(appDomain, o);
  o += APPLICATION_DOMAIN_LEN;
  out[o++] = format;
  out[o++] = 0x01; // signer count
  out.set(signerPublicKey, o);
  o += 32;
  out[o++] = msg.length & 0xff; // u16 little-endian length
  out[o++] = (msg.length >> 8) & 0xff;
  out.set(msg, o);
  return out;
}
