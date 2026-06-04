// Reveal-a-private-key hook.
//
// SECURITY (PRD §10 "Re-auth to reveal", docs/PRD_HOTFIX.md): reveal ALWAYS runs
// a fresh re-authentication ceremony and derives a one-time key — it never reads
// the ambient (possibly hot) session app key. That means a reveal cannot happen
// silently, and repeated Reveal → Hide → Reveal each require credentials again.
//
// The decrypted secret lives in React state only as long as the consumer holds
// it; `clear()` (or the auto-clear timer) releases it. JS strings can't be truly
// zeroed, so <ExportKeyPanel> keeps the window tight (auto-clear + clipboard wipe).
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { ReauthCredentials } from "../client/authClient.js";
import type { EncryptedWallet } from "../core/types.js";

export interface UseExportKeyOptions {
  /**
   * Auto-clear the revealed plaintext from state after this many milliseconds.
   * Defaults to no auto-clear — callers (or <ExportKeyPanel>) opt in.
   */
  autoClearMs?: number;
}

export interface UseExportKeyResult {
  /**
   * Run a re-auth ceremony and reveal the wallet's plaintext secret. Requires
   * credentials every time — there is no silent path.
   */
  reveal: (reauth: ReauthCredentials) => Promise<string>;
  /** Drops the plaintext from state. */
  clear: () => void;
  /** Currently revealed plaintext, or null. */
  plaintext: string | null;
  /** True while a reveal call is in flight. */
  loading: boolean;
  /** Error from the last reveal call, or null. */
  error: Error | null;
}

export function useExportKey(
  wallet: EncryptedWallet | null | undefined,
  options: UseExportKeyOptions = {},
): UseExportKeyResult {
  const { client } = useAuthContext();
  const { autoClearMs } = options;
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const revealSeq = useRef(0);

  const clear = useCallback(() => {
    revealSeq.current++;
    setPlaintext(null);
    setError(null);
  }, []);

  const reveal = useCallback(
    async (reauth: ReauthCredentials): Promise<string> => {
      if (!wallet) {
        const err = new Error("useExportKey: no wallet provided");
        setError(err);
        throw err;
      }
      const mySeq = ++revealSeq.current;
      setLoading(true);
      setError(null);
      try {
        // One-time derive + decrypt behind a fresh ceremony. Does NOT arm the session.
        const secret = await client.revealSecret(wallet, reauth);
        if (mySeq === revealSeq.current) setPlaintext(secret);
        return secret;
      } catch (e) {
        const err = e instanceof Error ? e : new Error(String(e));
        if (mySeq === revealSeq.current) setError(err);
        throw err;
      } finally {
        if (mySeq === revealSeq.current) setLoading(false);
      }
    },
    [wallet, client],
  );

  // Auto-clear timeout. Resets whenever a fresh plaintext is revealed.
  useEffect(() => {
    if (!plaintext || !autoClearMs) return;
    const t = setTimeout(() => {
      revealSeq.current++;
      setPlaintext(null);
    }, autoClearMs);
    return () => clearTimeout(t);
  }, [plaintext, autoClearMs]);

  return { reveal, clear, plaintext, loading, error };
}
