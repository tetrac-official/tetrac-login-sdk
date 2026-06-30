// Ledger (off-chain) login — the two failures a hardware wallet hits, fixed.
//
// (1) "server denied the signature": the server verifies the RAW login message,
//     but a Ledger signs the off-chain ENVELOPE. verifySolanaSignature now accepts
//     both, so a Ledger-signed challenge logs in while software stays byte-identical.
// (2) "the encrypted blob failed": the app key is SHA-256(hex(keySig)). ed25519 is
//     deterministic and the envelope is fixed, so a Ledger that registers and logs
//     in through the same off-chain path derives a STABLE app key — the wallet
//     bundle encrypted at register decrypts at login.
//
// The "device" is a real ed25519 keypair signing exactly what it is handed:
//   - software wallet  → signs the raw message bytes
//   - hardware wallet  → signs encodeOffchainMessage(message, pubkey)
import nacl from "tweetnacl";
import { Keypair } from "@solana/web3.js";
import { verifySolanaSignature } from "../src/server/signature";
import {
  walletLoginMessage,
  walletAppKeyMessage,
  encodeOffchainMessage,
  deriveAppKeyFromSignature,
  generateChallenge,
} from "../src/core/index";

const enc = (s: string) => new TextEncoder().encode(s);
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// Mirrors the SDK's signMessage contract for each wallet kind.
function softwareSign(kp: Keypair, message: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, kp.secretKey);
}
function ledgerSign(kp: Keypair, message: Uint8Array): Uint8Array {
  const envelope = encodeOffchainMessage(message, kp.publicKey.toBytes());
  return nacl.sign.detached(envelope, kp.secretKey);
}

describe("verifySolanaSignature — hardware (off-chain) + software (raw)", () => {
  it("accepts a software wallet's RAW signature (no regression)", () => {
    const kp = Keypair.generate();
    const challenge = generateChallenge();
    const sig = softwareSign(kp, enc(walletLoginMessage(challenge)));
    expect(verifySolanaSignature(kp.publicKey.toBase58(), toHex(sig), challenge)).toBe(true);
  });

  it("accepts a Ledger's OFF-CHAIN envelope signature (fixes the 401)", () => {
    const kp = Keypair.generate();
    const challenge = generateChallenge();
    const sig = ledgerSign(kp, enc(walletLoginMessage(challenge)));
    // Before the fix this returned false → 401 Invalid credentials.
    expect(verifySolanaSignature(kp.publicKey.toBase58(), toHex(sig), challenge)).toBe(true);
  });

  it("rejects a signature bound to a DIFFERENT challenge (replay protection intact)", () => {
    const kp = Keypair.generate();
    const sig = ledgerSign(kp, enc(walletLoginMessage(generateChallenge())));
    expect(verifySolanaSignature(kp.publicKey.toBase58(), toHex(sig), generateChallenge())).toBe(false);
  });

  it("rejects a valid envelope signature presented under a DIFFERENT public key", () => {
    const signer = Keypair.generate();
    const impostor = Keypair.generate();
    const challenge = generateChallenge();
    const sig = ledgerSign(signer, enc(walletLoginMessage(challenge)));
    // The envelope embeds the signer pubkey; verifying under the impostor's key fails.
    expect(verifySolanaSignature(impostor.publicKey.toBase58(), toHex(sig), challenge)).toBe(false);
  });

  it("rejects garbage signatures", () => {
    const kp = Keypair.generate();
    expect(verifySolanaSignature(kp.publicKey.toBase58(), "00".repeat(64), generateChallenge())).toBe(false);
    expect(verifySolanaSignature(kp.publicKey.toBase58(), "nothex", generateChallenge())).toBe(false);
  });
});

describe("Ledger app-key derivation is stable (fixes the encrypted-blob failure)", () => {
  it("derives the SAME app key on register and on a later login (deterministic envelope)", () => {
    const kp = Keypair.generate();
    // Register: derive app key from the off-chain signature over the FIXED key message.
    const appKeyAtRegister = deriveAppKeyFromSignature(
      toHex(ledgerSign(kp, enc(walletAppKeyMessage("demo")))),
    );
    // Login (later, separate signing ceremony): same wallet, same message, same envelope.
    const appKeyAtLogin = deriveAppKeyFromSignature(toHex(ledgerSign(kp, enc(walletAppKeyMessage("demo")))));
    expect(appKeyAtLogin).toBe(appKeyAtRegister);
  });

  it("derives a DIFFERENT app key per appId (domain separation preserved for hardware)", () => {
    const kp = Keypair.generate();
    const a = deriveAppKeyFromSignature(toHex(ledgerSign(kp, enc(walletAppKeyMessage("app-a")))));
    const b = deriveAppKeyFromSignature(toHex(ledgerSign(kp, enc(walletAppKeyMessage("app-b")))));
    expect(a).not.toBe(b);
  });

  it("a Ledger and a software wallet for the SAME key derive DIFFERENT app keys (the mixing footgun)", () => {
    // This is WHY a blob registered as software fails to decrypt on a Ledger login:
    // the two sign different preimages, so the app keys differ. Register and log in
    // through the SAME path and the blob round-trips.
    const kp = Keypair.generate();
    const sw = deriveAppKeyFromSignature(toHex(softwareSign(kp, enc(walletAppKeyMessage("demo")))));
    const hw = deriveAppKeyFromSignature(toHex(ledgerSign(kp, enc(walletAppKeyMessage("demo")))));
    expect(hw).not.toBe(sw);
  });
});
