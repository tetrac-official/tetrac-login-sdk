// Hook for accessing the in-session app key and decrypt-to-sign helpers.
import { useCallback } from "react";
import { getAppKey } from "../client/session.js";
import { decryptWalletSecret, toSolanaKeypair, withDecryptedKey } from "../client/wallet.js";
import type { EncryptedWallet } from "../core/types.js";

export function useSigner() {
  const appKey = getAppKey();

  const decrypt = useCallback(
    (wallet: EncryptedWallet) => {
      if (!appKey) throw new Error("No app key in session (locked or logged out)");
      return decryptWalletSecret(wallet, appKey);
    },
    [appKey],
  );

  const solanaKeypair = useCallback(
    (wallet: EncryptedWallet) => {
      if (!appKey) throw new Error("No app key in session (locked or logged out)");
      return toSolanaKeypair(wallet, appKey);
    },
    [appKey],
  );

  const sign = useCallback(
    <T>(wallet: EncryptedWallet, fn: (secret: string) => Promise<T> | T) => {
      if (!appKey) throw new Error("No app key in session (locked or logged out)");
      return withDecryptedKey(wallet, appKey, fn);
    },
    [appKey],
  );

  return { unlocked: !!appKey, decrypt, solanaKeypair, sign };
}
