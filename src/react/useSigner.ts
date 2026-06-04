// Hook for accessing the in-session app key and decrypt-to-sign helpers.
// Honors the vault lock: when locked (auto-lock idle, tab hidden, or logged out)
// every helper throws VaultLockedError instead of operating on a stale key.
import { useCallback } from "react";
import { getAppKey, touchVault, VaultLockedError } from "../client/session.js";
import { decryptWalletSecret, toSolanaKeypair, withDecryptedKey } from "../client/wallet.js";
import type { EncryptedWallet } from "../core/types.js";

export function useSigner() {
  const appKey = getAppKey(); // null when the vault is locked

  const decrypt = useCallback(
    (wallet: EncryptedWallet) => {
      if (!appKey) throw new VaultLockedError();
      touchVault();
      return decryptWalletSecret(wallet, appKey);
    },
    [appKey],
  );

  const solanaKeypair = useCallback(
    (wallet: EncryptedWallet) => {
      if (!appKey) throw new VaultLockedError();
      touchVault();
      return toSolanaKeypair(wallet, appKey);
    },
    [appKey],
  );

  const sign = useCallback(
    <T>(wallet: EncryptedWallet, fn: (secret: string) => Promise<T> | T) => {
      if (!appKey) throw new VaultLockedError();
      touchVault(); // active use extends the unlocked window
      return withDecryptedKey(wallet, appKey, fn);
    },
    [appKey],
  );

  return { unlocked: !!appKey, decrypt, solanaKeypair, sign };
}
