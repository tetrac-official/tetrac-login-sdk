// Deterministic ed25519 "auth keypair" derived from the account's appKey.
//
// Email/biometric accounts authenticate by signing a server-issued challenge with
// this key; the server stores only the PUBLIC key — never a passkey hash. The seed
// is domain-separated from the appKey so the auth key and the wallet-encryption key
// are independent. ed25519 via tweetnacl — the same primitive the server already
// verifies for wallet logins.
import nacl from "tweetnacl";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { authLoginMessage } from "../core/index.js";

/** 32-byte ed25519 seed = SHA-256("ttc-auth-v1:" + appKey). appKey is already high-entropy. */
function authSeed(appKey: string): Uint8Array {
  return sha256(utf8ToBytes("ttc-auth-v1:" + appKey));
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
