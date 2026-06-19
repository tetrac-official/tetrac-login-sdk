// Safe-reveal UI for an encrypted private key.
//
// SECURITY (docs/PRD_HOTFIX.md): every reveal runs a fresh re-auth ceremony —
// passkey (email), Face ID / Touch ID (biometric), or a wallet signature
// (wallet). The plaintext is derived one-time from those credentials, never from
// the ambient session key, so Reveal → Hide → Reveal asks again each time. The
// panel also owns the auxiliary UX: auto-clear timeout, clipboard auto-wipe, and
// the React-Native-WebView postMessage contract.
//
// XSS note: any script on this page can read the revealed text while it's in
// state. Treat the reveal route as security-sensitive — strong CSP, no untrusted
// third-party scripts.
import React, { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { useExportKey, useUser, type ReauthCredentials } from "@tetrac/login-sdk/react";
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
    "Anyone with this key controls the wallet. Never share it. Revealing requires re-authentication; the view auto-clears after a minute.",
  cleared: "Hidden",
};

type RNWebViewWindow = { ReactNativeWebView?: { postMessage: (msg: string) => void } };
function postToRN(message: object): void {
  const rn =
    typeof window !== "undefined" ? (window as unknown as RNWebViewWindow).ReactNativeWebView : undefined;
  if (rn) rn.postMessage(JSON.stringify(message));
}

export function ExportKeyPanel(props: ExportKeyPanelProps) {
  const {
    wallet,
    autoClearMs = DEFAULT_AUTO_CLEAR_MS,
    clipboardClearMs = DEFAULT_CLIPBOARD_CLEAR_MS,
    postToReactNativeWebView = false,
    title = "Export private key",
    description,
    passkeyRegistration,
    walletSignMessage,
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

  // The account's auth method drives which ceremony we render.
  const { user } = useUser();
  const method = user?.authMethod ?? null;

  const { reveal, clear, plaintext, loading, error } = useExportKey(wallet, {
    autoClearMs: autoClearMs > 0 ? autoClearMs : undefined,
  });

  const [passkey, setPasskey] = useState("");
  const [copiedFlash, setCopiedFlash] = useState(false);

  useEffect(() => {
    if (plaintext) onReveal?.(plaintext);
  }, [plaintext, onReveal]);
  useEffect(() => {
    if (error) onError?.(error);
  }, [error, onError]);

  useEffect(() => {
    if (!postToReactNativeWebView) return;
    if (plaintext) postToRN({ status: "success", privateKey: plaintext });
  }, [plaintext, postToReactNativeWebView]);
  useEffect(() => {
    if (!postToReactNativeWebView) return;
    if (error) postToRN({ status: "error", error: error.message });
  }, [error, postToReactNativeWebView]);

  // Run the ceremony for the active method and reveal.
  const doReveal = useCallback(
    async (creds: ReauthCredentials) => {
      try {
        await reveal(creds);
        setPasskey(""); // never keep the typed passkey around after use
      } catch {
        // The hook captures the error in state; surfaced inline below.
      }
    },
    [reveal],
  );

  const handleCopy = useCallback(async () => {
    if (!plaintext) return;
    try {
      await navigator.clipboard.writeText(plaintext);
      setCopiedFlash(true);
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

  useEffect(() => {
    if (!copiedFlash) return;
    const t = setTimeout(() => setCopiedFlash(false), 1500);
    return () => clearTimeout(t);
  }, [copiedFlash]);

  // --- Ceremony UI (shown until a plaintext is revealed) ---
  function renderCeremony() {
    if (!wallet) {
      return (
        <span className={classNames?.muted} style={styles.muted}>
          No wallet to export.
        </span>
      );
    }
    if (!method) {
      return (
        <span className={classNames?.muted} style={styles.muted}>
          Loading account…
        </span>
      );
    }

    if (method === "biometric") {
      return (
        <>
          <button
            type="button"
            className={classNames?.primaryButton}
            style={styles.primaryButton}
            onClick={() => passkeyRegistration && doReveal({ registration: passkeyRegistration })}
            disabled={loading || !passkeyRegistration}
          >
            {loading ? "…" : "Confirm with Face ID / Touch ID to reveal"}
          </button>
          {!passkeyRegistration ? (
            <span className={classNames?.muted} style={styles.muted}>
              Pass `passkeyRegistration` to enable biometric reveal.
            </span>
          ) : null}
        </>
      );
    }

    if (method === "wallet") {
      return (
        <>
          <button
            type="button"
            className={classNames?.primaryButton}
            style={styles.primaryButton}
            onClick={() => walletSignMessage && doReveal({ signMessage: walletSignMessage })}
            disabled={loading || !walletSignMessage}
          >
            {loading ? "…" : "Sign with your wallet to reveal"}
          </button>
          {!walletSignMessage ? (
            <span className={classNames?.muted} style={styles.muted}>
              Pass `walletSignMessage` to enable wallet reveal.
            </span>
          ) : null}
        </>
      );
    }

    // email (default): re-enter the passkey.
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (passkey) void doReveal({ passkey });
        }}
        style={{ display: "flex", flexDirection: "column", gap: 8 }}
      >
        <input
          type="password"
          autoComplete="current-password"
          placeholder="Enter your passkey to reveal"
          value={passkey}
          onChange={(e) => setPasskey(e.target.value)}
          className={classNames?.input}
          style={styles.input}
        />
        <button
          type="submit"
          className={classNames?.primaryButton}
          style={styles.primaryButton}
          disabled={loading || !passkey}
        >
          {loading ? "…" : copy.reveal}
        </button>
      </form>
    );
  }

  return (
    <div className={[className, classNames?.root].filter(Boolean).join(" ") || undefined} style={styles.root}>
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
        renderCeremony()
      ) : (
        <>
          <div className={classNames?.secretBlock} style={styles.secretBlock}>
            {plaintext}
          </div>
          <div className={classNames?.actions} style={styles.actions}>
            <button type="button" className={classNames?.button} style={styles.button} onClick={handleCopy}>
              {copiedFlash ? copy.copied : copy.copy}
            </button>
            <button type="button" className={classNames?.button} style={styles.button} onClick={clear}>
              {copy.hide}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
