// Deterministic ed25519 "auth keypair" derived from the account's appKey.
//
// Email/biometric accounts authenticate by signing a server-issued challenge with
// this key; the server stores only the PUBLIC key — never a passkey hash. The seed
// is domain-separated from the appKey so the auth key and the wallet-encryption key
// are independent. ed25519 via tweetnacl — the same primitive the server already
// verifies for wallet logins.
import nacl from "tweetnacl";
import CryptoES from "crypto-es";
import { authLoginMessage } from "../core/index.js";

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** 32-byte ed25519 seed = SHA-256("ttc-auth-v1:" + appKey). appKey is already high-entropy. */
function authSeed(appKey: string): Uint8Array<ArrayBuffer> {
  return hexToBytes(CryptoES.SHA256("ttc-auth-v1:" + appKey).toString(CryptoES.enc.Hex));
}

/** Public key (hex) of the account's auth keypair — the only auth credential the server stores. */
export function deriveAuthPublicKey(appKey: string): string {
  return bytesToHex(nacl.sign.keyPair.fromSeed(authSeed(appKey)).publicKey);
}

/** Sign a server login challenge with the account's auth keypair. Returns the signature (hex). */
export function signAuthChallenge(appKey: string, challenge: string): string {
  const kp = nacl.sign.keyPair.fromSeed(authSeed(appKey));
  const msg = new TextEncoder().encode(authLoginMessage(challenge));
  return bytesToHex(nacl.sign.detached(msg, kp.secretKey));
}
