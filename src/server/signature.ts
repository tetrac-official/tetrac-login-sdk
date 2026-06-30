// Server-side Web3 signature verification (Solana, ed25519 via tweetnacl).
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import { walletLoginMessage, authLoginMessage, offchainMessageCandidates } from "../core/index.js";

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("Invalid hex signature length");
  // Reject non-hex characters explicitly. Without this, parseInt("GG",16) yields NaN
  // and silently coerces to a 0 byte — still fails the signature check, but failing
  // loudly here keeps the intent clear and avoids treating garbage as a zero key.
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error("Invalid hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Verify that `signatureHex` is a valid signature, by `publicKeyBase58`, over the
 * canonical wallet-login message built from `challenge`.
 *
 * Accepts BOTH encodings, trying the cheap one first:
 *  1. RAW — software wallets (Phantom et al.) sign the message bytes directly.
 *     Byte-identical to the original behavior; software accounts are unaffected.
 *  2. OFF-CHAIN — hardware wallets (Ledger) cannot sign raw bytes; they sign a
 *     Solana off-chain message envelope. The exact layout depends on the device
 *     firmware (legacy 20-byte header vs v0 85-byte header), so the server tries
 *     EVERY known candidate and accepts a match. The login message is pure ASCII.
 *
 * The off-chain attempt is NOT a trust widening: every candidate preimage embeds
 * the single-use `challenge` (and the v0 candidate embeds `pubKeyBytes` as the
 * signer), so a forged signature or a mismatched signer still fails. Replay
 * protection (single-use challenge) is unchanged.
 */
export function verifySolanaSignature(
  publicKeyBase58: string,
  signatureHex: string,
  challenge: string,
): boolean {
  try {
    const message = new TextEncoder().encode(walletLoginMessage(challenge));
    const sig = hexToBytes(signatureHex);
    const pubKeyBytes = new PublicKey(publicKeyBase58).toBytes();
    // 1) Raw (software wallets) — the default, unchanged path.
    if (nacl.sign.detached.verify(message, sig, pubKeyBytes)) return true;
    // 2) Off-chain envelopes (hardware wallets). offchainMessageCandidates throws
    //    on a non-ASCII/oversized message; the outer catch turns that into `false`.
    for (const envelope of offchainMessageCandidates(message, pubKeyBytes)) {
      if (nacl.sign.detached.verify(envelope, sig, pubKeyBytes)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Verify an email/biometric account's login: ed25519 signature over
 * authLoginMessage(challenge) by the account's stored auth public key (hex).
 * This is what replaces the old passkeyHash compare — the server stores only the
 * public key and never any passkey-derived secret.
 */
export function verifyAuthSignature(
  authPublicKeyHex: string,
  signatureHex: string,
  challenge: string,
): boolean {
  try {
    const message = new TextEncoder().encode(authLoginMessage(challenge));
    const sig = hexToBytes(signatureHex);
    const pub = hexToBytes(authPublicKeyHex);
    return nacl.sign.detached.verify(message, sig, pub);
  } catch {
    return false;
  }
}
