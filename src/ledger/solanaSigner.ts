// Adapts a Ledger device into the SDK's wallet-adapter-shaped `SolanaSigner`,
// so a hardware account is a drop-in for `useSolanaSigner(wallet)` anywhere a
// `SolanaSigner` is consumed (Anchor's AnchorProvider, wallet-adapter, etc.).
//
// KEYLESS: the only thing this receives from the device is a 64-byte signature.
// It is attached to the caller's transaction and never logged or persisted.
//
// This module is pure (no React) so it can be unit-tested without a device:
// inject the two raw device methods and it produces a full signer.
import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { encodeOffchainMessage } from "../core/offchainMessage.js";
import type { SolanaSigner } from "../react/useSolanaSigner.js";

export interface LedgerSolanaSignerDeps {
  /** base58 address of the signing account — becomes the signer's `publicKey`. */
  address: string;
  /** BIP-32 path of the signing account (with or without the `m/` prefix). */
  path: string;
  /** Raw device call: sign a serialized transaction message, returns 64-byte sig. */
  signTransaction: (path: string, message: Uint8Array) => Promise<Uint8Array>;
  /** Raw device call: sign a fully-formed off-chain message envelope. */
  signOffchainMessage: (path: string, envelope: Uint8Array) => Promise<Uint8Array>;
}

function assert64(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new Error(`Ledger returned a ${signature.length}-byte signature (expected 64).`);
  }
  return signature;
}

/**
 * Build a {@link SolanaSigner} backed by a Ledger device account.
 *
 * - `signTransaction` / `signAllTransactions` serialize the transaction MESSAGE
 *   (legacy: `serializeMessage()`; v0: `message.serialize()`, which already
 *   carries the 0x80 version prefix), have the device sign it, then reattach the
 *   signature under this account's public key. Each call prompts the device;
 *   `signAllTransactions` prompts once per transaction, sequentially (a Ledger
 *   transport handles one APDU exchange at a time).
 * - `signMessage` wraps the bytes in the Solana off-chain message envelope and
 *   calls `signOffchainMessage`. NOTE: the resulting signature verifies against
 *   that envelope per the Solana off-chain standard — not against the raw bytes
 *   (hardware wallets cannot produce a bare ed25519 signature over arbitrary
 *   data). Messages must be printable ASCII and ≤1212 bytes by default.
 */
export function createLedgerSolanaSigner(deps: LedgerSolanaSignerDeps): SolanaSigner {
  const publicKey = new PublicKey(deps.address);

  async function signOne<T extends Transaction | VersionedTransaction>(tx: T): Promise<T> {
    if (tx instanceof VersionedTransaction) {
      const signature = assert64(await deps.signTransaction(deps.path, tx.message.serialize()));
      // VersionedTransaction stores the signature BY REFERENCE; copy so a later
      // mutation/reuse of the device buffer can't corrupt the attached signature
      // (legacy's addSignature copies internally, so this keeps the two symmetric).
      tx.addSignature(publicKey, new Uint8Array(signature));
    } else {
      const message = (tx as Transaction).serializeMessage();
      const signature = assert64(await deps.signTransaction(deps.path, message));
      // Transaction.addSignature is typed `Buffer` but web3.js re-wraps with its
      // own `Buffer.from` internally, so a Uint8Array is safe at runtime.
      (tx as Transaction).addSignature(publicKey, signature as unknown as Buffer);
    }
    return tx;
  }

  return {
    publicKey,
    signTransaction: signOne,
    // Signs sequentially, mutating each tx in place (one device prompt apiece) —
    // matching wallet-adapter semantics and the SDK's embedded useSolanaSigner.
    // A mid-batch rejection throws with earlier txs already signed (not atomic).
    signAllTransactions: async <T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]> => {
      const signed: T[] = [];
      for (const tx of txs) signed.push(await signOne(tx));
      return signed;
    },
    signMessage: async (message: Uint8Array): Promise<Uint8Array> => {
      const envelope = encodeOffchainMessage(message, publicKey.toBytes());
      return assert64(await deps.signOffchainMessage(deps.path, envelope));
    },
  };
}
