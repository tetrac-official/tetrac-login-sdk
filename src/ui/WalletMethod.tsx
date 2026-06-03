// Web3 wallet sub-panel. The SDK stays decoupled from any specific wallet lib —
// the host app supplies a `WalletConnector` whose `connect()` resolves to the
// public key + signMessage pair that `connectWallet` needs.
import React, { useState, type CSSProperties } from "react";
// Public subpath import — see EmailMethod.tsx for why we avoid `../react/...`.
import { useAuth } from "@tetrac/login-sdk/react";
import type { AuthResult } from "../core/types.js";
import type { LoginPanelProps, WalletConnector } from "./types.js";

export interface WalletMethodProps {
  connector: WalletConnector;
  styles: Record<string, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  onSuccess: (result: AuthResult) => void;
  onError: (err: Error) => void;
}

export function WalletMethod({ connector, styles, classNames, onSuccess, onError }: WalletMethodProps) {
  const { connectWallet } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const { publicKey, signMessage } = await connector.connect();
      // connectWallet = register if new, login if known — one round trip.
      const result = await connectWallet({ publicKey, signMessage });
      onSuccess(result);
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e.message);
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={classNames?.method} style={styles.method}>
      <span className={classNames?.methodLabel} style={styles.methodLabel}>
        Wallet
      </span>
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className={classNames?.button}
        style={styles.button}
      >
        {busy ? "Waiting for signature…" : (connector.label ?? "Continue with wallet")}
      </button>
      {error ? (
        <span className={classNames?.error} style={styles.error}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
