// Flat wallet list for the active session: embedded wallets + any connected external.
import { useMemo } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { Chain, EncryptedWallet, WalletRole } from "../core/types.js";

export interface WalletEntry {
  chain: Chain;
  role: WalletRole;
  address: string;
  isEmbedded: boolean;
  /** The encrypted blob for embedded wallets; null for externally connected wallets. */
  encrypted: EncryptedWallet | null;
}

export function useWallets(): WalletEntry[] {
  const { user, externalSolanaAddress } = useAuthContext();

  return useMemo(() => {
    const out: WalletEntry[] = [];
    if (externalSolanaAddress) {
      out.push({
        chain: "solana",
        role: "funds",
        address: externalSolanaAddress,
        isEmbedded: false,
        encrypted: null,
      });
    }
    for (const w of user?.wallets ?? []) {
      out.push({
        chain: w.chain,
        role: w.role,
        address: w.publicKey,
        isEmbedded: true,
        encrypted: w,
      });
    }
    return out;
  }, [user, externalSolanaAddress]);
}
