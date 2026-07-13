// Flat wallet list for the active session: embedded wallets + any connected external.
import { useMemo } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { Chain, EncryptedWallet, WalletRole } from "../core/types.js";

export interface WalletEntry {
  chain: Chain;
  role: WalletRole;
  address: string;
  isEmbedded: boolean;
  /**
   * True for the ONE wallet that is the account's login identity (`UserData.publicKey`):
   * the embedded Solana funds wallet for email/biometric accounts, or the connected
   * Web3 wallet for `authMethod: "wallet"` accounts.
   *
   * Use this — not `role === "funds"` — to answer "which wallet is the user?". A Web3
   * account can carry a *second* Solana wallet also tagged `role: "funds"` (see below),
   * and picking the wrong one means showing the wrong deposit address. (v0.5.1)
   */
  isIdentity: boolean;
  /** The encrypted blob for embedded wallets; null for externally connected wallets. */
  encrypted: EncryptedWallet | null;
}

export function useWallets(): WalletEntry[] {
  const { user, externalSolanaAddress } = useAuthContext();

  return useMemo(() => {
    const out: WalletEntry[] = [];

    // For a Web3 account, the connected wallet IS the identity and IS the Solana funds
    // wallet. Derive it from the RECORD (`user.publicKey`), never from
    // `externalSolanaAddress` alone: that is an app-supplied prop which is null whenever
    // the wallet adapter isn't connected in this browser session, and the SDK session
    // outlives the adapter connection.
    const web3Identity = user?.authMethod === "wallet" ? user.publicKey : null;
    const solanaExternal = web3Identity ?? externalSolanaAddress;

    if (solanaExternal) {
      out.push({
        chain: "solana",
        role: "funds",
        address: solanaExternal,
        isEmbedded: false,
        isIdentity: solanaExternal === user?.publicKey,
        encrypted: null, // the SDK never holds an external wallet's key — it cannot be exported
      });
    }

    // Embedded wallets, as stored. NOTE: accounts created before v0.5.1 with a Web3 login
    // may carry a REDUNDANT embedded Solana `funds` wallet that should never have been
    // generated. It is still listed here — deliberately — because it is a real key that may
    // hold a real balance, and hiding it would strand those funds. It just isn't the
    // identity (`isIdentity: false`), so it can no longer masquerade as the user's wallet.
    for (const w of user?.wallets ?? []) {
      out.push({
        chain: w.chain,
        role: w.role,
        address: w.publicKey,
        isEmbedded: true,
        isIdentity: w.publicKey === user?.publicKey,
        encrypted: w,
      });
    }
    return out;
  }, [user, externalSolanaAddress]);
}
