// Safe-reveal UI for an encrypted private key. Self-custody means the
// plaintext lands in the app's DOM (there's no Privy-style iframe sandbox),
// so this panel owns the auxiliary UX that an app should NOT have to
// re-implement: auto-clear timeout, clipboard auto-wipe, and the
// React-Native-WebView postMessage contract.
//
// Apps that don't import from `@tetrac/login-sdk/ui` pay nothing for it.
//
// XSS note: any script on this page can read the revealed text while it's
// in state. Treat the reveal route as security-sensitive — strong CSP, no
// untrusted third-party scripts.
import React, { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { useExportKey } from "@tetrac/login-sdk/react";
import { buildExportKeyStyles } from "./styles.js";
import type { ExportKeyPanelProps, ExportKeyPanelSlot } from "./types.js";

const DEFAULT_AUTO_CLEAR_MS = 60_000;
const DEFAULT_CLIPBOARD_CLEAR_MS = 30_000;

const DEFAULT_LABELS = {
  reveal: "Reveal private key",
  copy: "Copy",
  copied: "Copied",
  hide: "Hide",
  warning:
    "Anyone with this key controls the wallet. Never share it. The view auto-clears after a minute.",
  cleared: "Hidden",
};

// Best-effort RN-WebView bridge. Matches Privy's reveal-flow contract so
// existing mobile shells keep working when the SDK replaces Privy.
type RNWebViewWindow = { ReactNativeWebView?: { postMessage: (msg: string) => void } };
function postToRN(message: object): void {
  const rn = (typeof window !== "undefined" ? (window as unknown as RNWebViewWindow).ReactNativeWebView : undefined);
  if (rn) rn.postMessage(JSON.stringify(message));
}

export function ExportKeyPanel(props: ExportKeyPanelProps) {
  const {
    wallet,
    autoClearMs = DEFAULT_AUTO_CLEAR_MS,
    clipboardClearMs = DEFAULT_CLIPBOARD_CLEAR_MS,
    postToReactNativeWebView = true,
    title = "Export private key",
    description,
    className,
    classNames,
    styles: stylesOverride,
    appearance,
    labels,
    onReveal,
    onError,
  } = props;

  const styles = useMemo(() => {
    const base = buildExportKeyStyles(appearance);
    if (!stylesOverride) return base;
    const merged: Record<ExportKeyPanelSlot, CSSProperties> = { ...base };
    (Object.keys(stylesOverride) as ExportKeyPanelSlot[]).forEach((slot) => {
      merged[slot] = { ...base[slot], ...stylesOverride[slot] };
    });
    return merged;
  }, [appearance, stylesOverride]);

  const copy = { ...DEFAULT_LABELS, ...labels };

  // Passing 0 disables the hook-level auto-clear; we still pass it through so
  // the hook owns the timer (one source of truth).
  const { reveal, clear, plaintext, loading, error } = useExportKey(wallet, {
    autoClearMs: autoClearMs > 0 ? autoClearMs : undefined,
  });

  const [copiedFlash, setCopiedFlash] = useState(false);

  // Notify callers when a reveal lands or fails.
  useEffect(() => {
    if (plaintext) onReveal?.(plaintext);
  }, [plaintext, onReveal]);
  useEffect(() => {
    if (error) onError?.(error);
  }, [error, onError]);

  // RN-WebView postMessage: fires on both success and the most recent error.
  useEffect(() => {
    if (!postToReactNativeWebView) return;
    if (plaintext) postToRN({ status: "success", privateKey: plaintext });
  }, [plaintext, postToReactNativeWebView]);
  useEffect(() => {
    if (!postToReactNativeWebView) return;
    if (error) postToRN({ status: "error", error: error.message });
  }, [error, postToReactNativeWebView]);

  const handleReveal = useCallback(async () => {
    try {
      await reveal();
    } catch {
      // The hook captures the error in state; we surface it inline below.
    }
  }, [reveal]);

  const handleCopy = useCallback(async () => {
    if (!plaintext) return;
    try {
      await navigator.clipboard.writeText(plaintext);
      setCopiedFlash(true);
      // Best-effort: overwrite the clipboard after the configured delay. Only
      // works while the page stays focused; we can't promise it but it's
      // significantly better than leaving the key on the clipboard indefinitely.
      if (clipboardClearMs > 0) {
        setTimeout(() => {
          navigator.clipboard.writeText("").catch(() => {
            /* ignore — page may be unfocused */
          });
        }, clipboardClearMs);
      }
    } catch {
      // Clipboard API can throw on non-secure contexts / permission denied.
    }
  }, [plaintext, clipboardClearMs]);

  // Briefly flash "Copied" then revert the button label.
  useEffect(() => {
    if (!copiedFlash) return;
    const t = setTimeout(() => setCopiedFlash(false), 1500);
    return () => clearTimeout(t);
  }, [copiedFlash]);

  return (
    <div
      className={[className, classNames?.root].filter(Boolean).join(" ") || undefined}
      style={styles.root}
    >
      {title !== null ? (
        <h2 className={classNames?.title} style={styles.title}>
          {title}
        </h2>
      ) : null}

      <p className={classNames?.description} style={styles.description}>
        {description ?? copy.warning}
      </p>

      {error ? (
        <div className={classNames?.error} style={styles.error}>
          {error.message}
        </div>
      ) : null}

      {!plaintext ? (
        <button
          type="button"
          className={classNames?.primaryButton}
          style={styles.primaryButton}
          onClick={handleReveal}
          disabled={loading || !wallet}
        >
          {loading ? "…" : copy.reveal}
        </button>
      ) : (
        <>
          <div className={classNames?.secretBlock} style={styles.secretBlock}>
            {plaintext}
          </div>
          <div className={classNames?.actions} style={styles.actions}>
            <button
              type="button"
              className={classNames?.button}
              style={styles.button}
              onClick={handleCopy}
            >
              {copiedFlash ? copy.copied : copy.copy}
            </button>
            <button
              type="button"
              className={classNames?.button}
              style={styles.button}
              onClick={clear}
            >
              {copy.hide}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
