// Server-side Web3 signature verification (Solana, ed25519 via tweetnacl).
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import { walletLoginMessage, authLoginMessage } from "../core/index.js";

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
    return nacl.sign.detached.verify(message, sig, pubKeyBytes);
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
