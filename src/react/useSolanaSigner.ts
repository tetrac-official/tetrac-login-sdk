// Ready-made Solana signer in @solana/wallet-adapter-react shape.
// Built on useSigner / withDecryptedKey — the secret is decrypted only for the
// duration of each signing call, then released.
import { useMemo } from "react";
import { Keypair, PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import nacl from "tweetnacl";
import { useSigner } from "./useSigner.js";
import type { EncryptedWallet } from "../core/types.js";

export interface SolanaSigner {
  publicKey: PublicKey;
  signTransaction: <T extends Transaction | VersionedTransaction>(tx: T) => Promise<T>;
  signAllTransactions: <T extends Transaction | VersionedTransaction>(txs: T[]) => Promise<T[]>;
  signMessage: (message: Uint8Array) => Promise<Uint8Array>;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function partialSign<T extends Transaction | VersionedTransaction>(tx: T, kp: Keypair): void {
  if (tx instanceof VersionedTransaction) tx.sign([kp]);
  else (tx as Transaction).partialSign(kp);
}

/**
 * Drop-in Solana signer for an encrypted wallet. Returns `null` when no wallet
 * is provided or the session is locked. The returned object matches the shape
 * expected by `@solana/wallet-adapter-react` and Anchor's `AnchorProvider`.
 */
export function useSolanaSigner(wallet: EncryptedWallet | null | undefined): SolanaSigner | null {
  const { sign, unlocked } = useSigner();

  return useMemo(() => {
    if (!wallet || !unlocked) return null;
    if (wallet.chain !== "solana") {
      throw new Error(`useSolanaSigner: expected Solana wallet, got chain="${wallet.chain}"`);
    }

    const publicKey = new PublicKey(wallet.publicKey);

    return {
      publicKey,
      signTransaction: (tx) =>
        sign(wallet, (secret) => {
          const kp = Keypair.fromSecretKey(hexToBytes(secret));
          try {
            partialSign(tx, kp);
            return tx;
          } finally {
            kp.secretKey.fill(0);
          }
        }),
      signAllTransactions: (txs) =>
        sign(wallet, (secret) => {
          const kp = Keypair.fromSecretKey(hexToBytes(secret));
          try {
            for (const tx of txs) partialSign(tx, kp);
            return txs;
          } finally {
            kp.secretKey.fill(0);
          }
        }),
      signMessage: (message) =>
        sign(wallet, (secret) => {
          const sk = hexToBytes(secret);
          try {
            return nacl.sign.detached(message, sk);
          } finally {
            sk.fill(0);
          }
        }),
    };
  }, [wallet, sign, unlocked]);
}
