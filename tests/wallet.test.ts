import { Keypair } from "@solana/web3.js";
import {
  generateWalletBundle,
  flattenBundle,
  decryptWalletSecret,
  toSolanaKeypair,
  withDecryptedKey,
} from "../src/client/wallet";
import { deriveAppKeyFromPasskey } from "../src/core/crypto";

const appKey = deriveAppKeyFromPasskey("pw", "a@b.com");

describe("generateWalletBundle", () => {
  it("generates requested roles per chain, encrypted", () => {
    const bundle = generateWalletBundle({ appKey, solana: ["funds", "signing"], evm: ["funds", "signing"] });
    expect(Object.keys(bundle.solana!)).toEqual(["funds", "signing"]);
    expect(Object.keys(bundle.evm!)).toEqual(["funds", "signing"]);

    const sf = bundle.solana!.funds!;
    expect(sf.publicKey).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/); // base58
    expect(sf.encryptedSecret).not.toContain(sf.publicKey);

    const ef = bundle.evm!.funds!;
    expect(ef.publicKey).toMatch(/^0x[0-9a-fA-F]{40}$/); // EVM address
  });

  it("supports requesting a single role", () => {
    const bundle = generateWalletBundle({ appKey, solana: ["funds"] });
    expect(Object.keys(bundle.solana!)).toEqual(["funds"]);
    expect(bundle.evm).toBeUndefined();
  });

  it("flattens to public keys + ciphertext only (no plaintext secrets)", () => {
    const bundle = generateWalletBundle({ appKey, solana: ["funds"], evm: ["funds"] });
    const flat = flattenBundle(bundle);
    expect(flat).toHaveLength(2);
    for (const w of flat) {
      expect(w).toHaveProperty("publicKey");
      expect(w).toHaveProperty("encryptedSecret");
      expect(w).not.toHaveProperty("secret");
    }
  });
});

describe("decrypt-to-sign", () => {
  it("reconstructs a usable Solana keypair", () => {
    const bundle = generateWalletBundle({ appKey, solana: ["funds"] });
    const wallet = bundle.solana!.funds!;
    const kp = toSolanaKeypair(wallet, appKey);
    expect(kp).toBeInstanceOf(Keypair);
    expect(kp.publicKey.toBase58()).toBe(wallet.publicKey);
  });

  it("decrypts the EVM private key as 0x hex", () => {
    const bundle = generateWalletBundle({ appKey, evm: ["signing"] });
    const secret = decryptWalletSecret(bundle.evm!.signing!, appKey);
    expect(secret).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("withDecryptedKey exposes the secret only inside the callback", async () => {
    const bundle = generateWalletBundle({ appKey, solana: ["funds"] });
    const result = await withDecryptedKey(bundle.solana!.funds!, appKey, (secret) => {
      expect(secret).toMatch(/^[0-9a-f]+$/);
      return secret.length;
    });
    expect(result).toBe(128); // 64-byte secret as hex
  });
});
