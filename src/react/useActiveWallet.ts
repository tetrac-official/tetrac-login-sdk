// The one wallet the app should sign/display with for a given chain.
//
// Rule (Solana): a Web3 account's identity wallet ALWAYS wins — it is the wallet the user
// logged in with. Otherwise an externally connected wallet wins. Otherwise the embedded
// funds wallet.
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
    if (chain === "solana") {
      // A Web3 account's Solana funds wallet is the wallet it logged in with, full stop.
      // Resolve it from the RECORD, not from `externalSolanaAddress` — that prop is null
      // whenever the wallet adapter isn't connected in this browser session (and the SDK
      // session outlives the adapter connection). Falling through to an embedded wallet
      // there would hand the app the WRONG Solana address. For accounts created before
      // v0.5.1 a stray embedded Solana `funds` wallet actually exists, so this is not
      // hypothetical: an app rendering it as a deposit address would send the user's funds
      // to a wallet they don't know they own.
      const web3Identity = user?.authMethod === "wallet" ? user.publicKey : null;
      const address = web3Identity ?? externalSolanaAddress;
      if (address) {
        return {
          chain: "solana",
          role: "funds",
          address,
          isEmbedded: false,
          isIdentity: address === user?.publicKey,
          encrypted: null, // an external key is not the SDK's to hold, sign with, or export
        };
      }
    }

    const funds = user?.wallets.find((w) => w.chain === chain && w.role === "funds");
    if (!funds) return null;
    return {
      chain: funds.chain,
      role: funds.role,
      address: funds.publicKey,
      isEmbedded: true,
      isIdentity: funds.publicKey === user?.publicKey,
      encrypted: funds,
    };
  }, [user, externalSolanaAddress, chain]);
}
