// The one wallet the app should sign/display with for a given chain.
// Rule: external connected wins for Solana; otherwise embedded funds wallet.
import { useMemo } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { Chain } from "../core/types.js";
import type { WalletEntry } from "./useWallets.js";

export interface UseActiveWalletOptions {
  /** Which chain's active wallet to return. Defaults to "solana". */
  chain?: Chain;
}

export function useActiveWallet(options: UseActiveWalletOptions = {}): WalletEntry | null {
  const { user, externalSolanaAddress } = useAuthContext();
  const chain = options.chain ?? "solana";

  return useMemo(() => {
    if (chain === "solana" && externalSolanaAddress) {
      return {
        chain: "solana",
        role: "funds",
        address: externalSolanaAddress,
        isEmbedded: false,
        encrypted: null,
      };
    }
    const funds = user?.wallets.find((w) => w.chain === chain && w.role === "funds");
    if (!funds) return null;
    return {
      chain: funds.chain,
      role: funds.role,
      address: funds.publicKey,
      isEmbedded: true,
      encrypted: funds,
    };
  }, [user, externalSolanaAddress, chain]);
}
