// Solana off-chain message envelope encoders — shared by the client Ledger
// signer (to build what the device signs) AND the server verifier (to
// reconstruct the same preimage and accept a hardware-wallet login signature).
// Lives in /core because it is pure, framework-agnostic byte work (no DOM, no
// React, no @ledgerhq) used on both sides of the wire.
//
// THERE ARE TWO REAL-WORLD LAYOUTS. The Ledger Solana app's accepted format
// depends on its firmware version, and there is no negotiation handshake — the
// device rejects an unexpected header with status 0x6a81. So callers must try
// the layouts in order (see offchainMessageCandidates) and verifiers must accept
// any of them. This mirrors LedgerHQ's own device-sdk-ts v0→legacy fallback.
//
//   LEGACY (older / currently most-deployed Solana app; the `solana
//   sign-offchain-message` CLI format) — 20-byte header:
//     signing domain   16  0xFF "solana offchain"
//     header version    1  0x00
//     message format    1  0 = RestrictedAscii, 1 = LimitedUtf8
//     message length    2  u16 little-endian
//     message          <length>
//
//   V0 / ANZA spec (newer firmware) — 85-byte header (single signer):
//     signing domain   16  0xFF "solana offchain"
//     header version    1  0x00
//     application domain 32 (all-zero = "no domain")
//     message format    1
//     signer count      1  0x01
//     signer pubkey    32  the signing account
//     message length    2  u16 little-endian
//     message          <length>
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
  /** 32-byte application domain (V0 layout only). Defaults to all-zero ("no domain"). */
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

/** Printable ASCII (0x20–0x7e) plus newline (0x0a) — what the RestrictedAscii format allows. */
function isPrintableAscii(bytes: Uint8Array): boolean {
  for (const c of bytes) {
    if (c === 0x0a) continue;
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/** Validate the message and resolve its format byte (shared by both layouts). */
function prepareMessage(
  message: Uint8Array | string,
  options: EncodeOffchainMessageOptions,
): { msg: Uint8Array; format: number } {
  const msg = typeof message === "string" ? new TextEncoder().encode(message) : message;
  if (msg.length === 0) {
    throw new Error("Ledger off-chain message: message must be non-empty.");
  }
  const maxLen = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  if (msg.length > maxLen) {
    throw new Error(
      `Ledger off-chain message: ${msg.length} bytes exceeds the ${maxLen}-byte on-device limit.`,
    );
  }
  if (isPrintableAscii(msg)) return { msg, format: FORMAT_RESTRICTED_ASCII };
  if (options.allowUtf8) {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(msg);
    } catch {
      throw new Error("Ledger off-chain message: message is not valid UTF-8.");
    }
    return { msg, format: FORMAT_LIMITED_UTF8 };
  }
  throw new Error(
    "Ledger off-chain message: only printable ASCII (and newlines) are supported by default. Pass { allowUtf8: true } to sign UTF-8 (the device then requires Blind Signing).",
  );
}

function u16le(out: Uint8Array, offset: number, value: number): void {
  out[offset] = value & 0xff;
  out[offset + 1] = (value >> 8) & 0xff;
}

/**
 * LEGACY off-chain message envelope (20-byte header) — the format the currently
 * most-deployed Ledger Solana app (and the `solana sign-offchain-message` CLI)
 * accepts. No application domain, no signer list.
 */
export function encodeOffchainMessageLegacy(
  message: Uint8Array | string,
  options: EncodeOffchainMessageOptions = {},
): Uint8Array {
  const { msg, format } = prepareMessage(message, options);
  const out = new Uint8Array(20 + msg.length);
  let o = 0;
  out.set(SIGNING_DOMAIN, o);
  o += SIGNING_DOMAIN.length;
  out[o++] = HEADER_VERSION_V0;
  out[o++] = format;
  u16le(out, o, msg.length);
  o += 2;
  out.set(msg, o);
  return out;
}

/**
 * V0 / Anza-spec off-chain message envelope (85-byte single-signer header) the
 * newer Ledger Solana firmware validates. `signerPublicKey` must be the 32-byte
 * ed25519 key of the signing account.
 *
 * @throws if the pubkey isn't 32 bytes, the message is empty/too long, or the
 *         message isn't ASCII (unless `allowUtf8` is set).
 */
export function encodeOffchainMessage(
  message: Uint8Array | string,
  signerPublicKey: Uint8Array,
  options: EncodeOffchainMessageOptions = {},
): Uint8Array {
  if (signerPublicKey.length !== 32) {
    throw new Error(
      `Ledger off-chain message: signer public key must be 32 bytes (got ${signerPublicKey.length}).`,
    );
  }
  const { msg, format } = prepareMessage(message, options);
  const appDomain = options.applicationDomain ?? new Uint8Array(APPLICATION_DOMAIN_LEN);
  if (appDomain.length !== APPLICATION_DOMAIN_LEN) {
    throw new Error(`Ledger off-chain message: applicationDomain must be ${APPLICATION_DOMAIN_LEN} bytes.`);
  }

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
  u16le(out, o, msg.length);
  o += 2;
  out.set(msg, o);
  return out;
}

/**
 * Every off-chain envelope a Ledger might sign for `message`, in the order a
 * client should try them (legacy first — what most deployed apps accept; v0 for
 * newer firmware). A signer cascades over these (falling back when the device
 * returns 0x6a81), and a verifier accepts a signature matching ANY of them.
 */
export function offchainMessageCandidates(
  message: Uint8Array | string,
  signerPublicKey: Uint8Array,
  options: EncodeOffchainMessageOptions = {},
): Uint8Array[] {
  return [
    encodeOffchainMessageLegacy(message, options),
    encodeOffchainMessage(message, signerPublicKey, options),
  ];
}
