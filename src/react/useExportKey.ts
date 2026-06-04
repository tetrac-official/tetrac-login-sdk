// Reveal-a-private-key hook. Wraps withDecryptedKey so the decrypted secret
// lives only as long as the consumer holds it in state — `clear()` releases
// the React reference. The SDK can't truly zero a JS string, so the auxiliary
// UX (auto-clear timeout, clipboard timeout, CSP) ships in <ExportKeyPanel>.
import { useCallback, useEffect, useRef, useState } from "react";
import { useSigner } from "./useSigner.js";
import type { EncryptedWallet } from "../core/types.js";

export interface UseExportKeyOptions {
  /**
   * Auto-clear the revealed plaintext from state after this many milliseconds.
   * Defaults to no auto-clear — callers (or <ExportKeyPanel>) opt in.
   */
  autoClearMs?: number;
}

export interface UseExportKeyResult {
  /** Decrypts the wallet secret, stores it in state, and returns it. */
  reveal: () => Promise<string>;
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
  const { sign, unlocked } = useSigner();
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

  const reveal = useCallback(async (): Promise<string> => {
    if (!wallet) {
      const err = new Error("useExportKey: no wallet provided");
      setError(err);
      throw err;
    }
    if (!unlocked) {
      const err = new Error("Session locked — sign in again to decrypt");
      setError(err);
      throw err;
    }
    const mySeq = ++revealSeq.current;
    setLoading(true);
    setError(null);
    try {
      const secret = await sign(wallet, (s) => s);
      if (mySeq === revealSeq.current) setPlaintext(secret);
      return secret;
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      if (mySeq === revealSeq.current) setError(err);
      throw err;
    } finally {
      if (mySeq === revealSeq.current) setLoading(false);
    }
  }, [wallet, unlocked, sign]);

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
