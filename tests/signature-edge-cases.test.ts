// Malformed-input hardening for server signature verification (src/server/signature.ts).
// server.test.ts covers the happy + forged-but-well-formed paths; this fills the
// hexToBytes validation branches (odd length, non-hex, 0x prefix) and the catch→false
// fall-throughs, so garbage input always fails closed instead of throwing.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { verifySolanaSignature, verifyAuthSignature } from "../src/server/signature";
import { walletLoginMessage, authLoginMessage } from "../src/core/index";

const CHALLENGE = "ab".repeat(32);

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

describe("verifySolanaSignature — malformed input fails closed", () => {
  const kp = Keypair.generate();
  const pub = kp.publicKey.toBase58();

  it("rejects an odd-length hex signature", () => {
    expect(verifySolanaSignature(pub, "abc", CHALLENGE)).toBe(false);
  });

  it("rejects a signature with non-hex characters", () => {
    expect(verifySolanaSignature(pub, "zz".repeat(64), CHALLENGE)).toBe(false);
  });

  it("rejects a well-formed but wrong signature", () => {
    expect(verifySolanaSignature(pub, "00".repeat(64), CHALLENGE)).toBe(false);
  });

  it("rejects an invalid base58 public key (PublicKey ctor throws → caught)", () => {
    expect(verifySolanaSignature("not valid base58 !!!", "00".repeat(64), CHALLENGE)).toBe(false);
  });

  it("tolerates a 0x-prefixed signature and still verifies a real one", () => {
    const sig = nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(CHALLENGE)), kp.secretKey);
    expect(verifySolanaSignature(pub, "0x" + bytesToHex(sig), CHALLENGE)).toBe(true); // 0x strip branch
    expect(verifySolanaSignature(pub, bytesToHex(sig), CHALLENGE)).toBe(true); // plain hex
  });
});

describe("verifyAuthSignature — malformed input fails closed", () => {
  const kp = nacl.sign.keyPair();
  const pubHex = bytesToHex(kp.publicKey);

  it("rejects a non-hex auth public key", () => {
    expect(verifyAuthSignature("zz".repeat(32), "00".repeat(64), CHALLENGE)).toBe(false);
  });

  it("rejects an odd-length signature", () => {
    expect(verifyAuthSignature(pubHex, "abc", CHALLENGE)).toBe(false);
  });

  it("verifies a real ed25519 auth signature", () => {
    const sig = nacl.sign.detached(new TextEncoder().encode(authLoginMessage(CHALLENGE)), kp.secretKey);
    expect(verifyAuthSignature(pubHex, bytesToHex(sig), CHALLENGE)).toBe(true);
  });
});
