// Ready-made EVM signer: a viem LocalAccount over an encrypted wallet.
// The private key is decrypted only for the duration of each signing call
// (via withDecryptedKey under useSigner), then released.
import { useMemo } from "react";
import type { Hex, LocalAccount } from "viem";
import { privateKeyToAccount, toAccount } from "viem/accounts";
import { useSigner } from "./useSigner.js";
import type { EncryptedWallet } from "../core/types.js";

/**
 * Drop-in viem `LocalAccount` over an encrypted EVM wallet. Returns `null`
 * when no wallet is provided or the session is locked. Pass into
 * `createWalletClient({ account })` to get a full wallet client.
 */
export function useEvmSigner(
  wallet: EncryptedWallet | null | undefined,
): LocalAccount | null {
  const { sign, unlocked } = useSigner();

  return useMemo(() => {
    if (!wallet || !unlocked) return null;
    if (wallet.chain !== "evm") {
      throw new Error(`useEvmSigner: expected EVM wallet, got chain="${wallet.chain}"`);
    }

    return toAccount({
      address: wallet.publicKey as `0x${string}`,
      signMessage: ({ message }) =>
        sign(wallet, (pk) => privateKeyToAccount(pk as Hex).signMessage({ message })),
      signTransaction: (transaction, options) =>
        sign(wallet, (pk) =>
          privateKeyToAccount(pk as Hex).signTransaction(transaction, options),
        ),
      signTypedData: (typedData) =>
        sign(wallet, (pk) => privateKeyToAccount(pk as Hex).signTypedData(typedData)),
    });
  }, [wallet, sign, unlocked]);
}
