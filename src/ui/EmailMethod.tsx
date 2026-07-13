// Email + passkey sub-panel. Wraps useAuth().{registerWithEmail,loginWithEmail}
// and implements the "auto" mode documented in USE_IN_CODE.md §4 (try register,
// fall back to login on 409).
import React, { useEffect, useMemo, useState, type CSSProperties } from "react";
// Import via the public subpath, not a relative path: a relative import causes
// tsup to inline `useAuth` + `AuthContext` into dist/ui/index.js, producing a
// second AuthContext instance that <AuthProvider> never populates. Treating the
// react subpath as external preserves a single shared context at runtime.
import { useAuth } from "@tetrac/login-sdk/react";
import type { AuthResult } from "../core/types.js";
import type { LoginPanelProps, PasskeyGeneratorConfig } from "./types.js";
import { generateStrongPasskey, DEFAULT_PASSKEY_BYTES } from "./passkey.js";

export interface EmailMethodProps {
  mode: NonNullable<LoginPanelProps["emailMode"]>;
  icon?: React.ReactNode;
  styles: Record<string, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  passkeyGenerator?: LoginPanelProps["passkeyGenerator"];
  onSuccess: (result: AuthResult) => void;
  onError: (err: Error) => void;
}

export function EmailMethod({
  mode,
  icon,
  styles,
  classNames,
  passkeyGenerator,
  onSuccess,
  onError,
}: EmailMethodProps) {
  const { registerWithEmail, loginWithEmail } = useAuth();
  const [email, setEmail] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The AUTO-revealed generated passkey (one-time, dismissible). Lives ONLY here
  // and in the `passkey` field — never persisted, logged, or transmitted.
  const [revealed, setRevealed] = useState<string | null>(null);
  const [copiedFlash, setCopiedFlash] = useState(false);

  // Resolve the generator config + gate on emailMode. Default follows emailMode:
  // shown for signup/auto, HIDDEN for signin. `showFor:"always"` overrides;
  // explicit "signup" pins to signup only; "auto" == default.
  const pkGenConfig = useMemo<PasskeyGeneratorConfig | null>(() => {
    if (!passkeyGenerator) return null;
    const cfg: PasskeyGeneratorConfig = typeof passkeyGenerator === "object" ? passkeyGenerator : {};
    const showFor = cfg.showFor ?? "auto";
    const visible =
      showFor === "always"
        ? true
        : showFor === "signup"
          ? mode === "signup"
          : /* "auto" (default) */ mode === "signup" || mode === "auto";
    return visible ? cfg : null;
  }, [passkeyGenerator, mode]);

  // Clear the revealed plaintext on unmount — never persisted, never logged.
  useEffect(() => {
    return () => setRevealed(null);
  }, []);

  // Transient "Copied" flash.
  useEffect(() => {
    if (!copiedFlash) return;
    const t = setTimeout(() => setCopiedFlash(false), 1500);
    return () => clearTimeout(t);
  }, [copiedFlash]);

  function handleGenerate() {
    if (busy || !pkGenConfig) return;
    const pk = generateStrongPasskey(pkGenConfig.bytes ?? DEFAULT_PASSKEY_BYTES);
    setPasskey(pk); // same state the input binds to → submit enables as if typed
    setRevealed(pk); // AUTO-reveal (DECIDED-3: safer against silent lockout)
    pkGenConfig.onGenerate?.(pk);
  }

  async function handleCopyReveal() {
    if (!revealed) return;
    try {
      await navigator.clipboard.writeText(revealed);
      setCopiedFlash(true);
      // NOTE (DECIDED-4): do NOT auto-wipe the clipboard here — a generated passkey
      // MUST be saved by the user (unlike ExportKeyPanel's ephemeral private key).
    } catch {
      // Best-effort: non-secure context / permission denied. The value stays
      // visible in the reveal block so the user can still copy it manually.
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      let result: AuthResult;
      if (mode === "signin") {
        result = await loginWithEmail({ email, passkey });
      } else if (mode === "signup") {
        result = await registerWithEmail({ email, passkey });
      } else {
        // "auto": try register, fall back to login if the account exists.
        try {
          result = await registerWithEmail({ email, passkey });
        } catch (err) {
          if (String(err).includes("already exists")) {
            result = await loginWithEmail({ email, passkey });
          } else {
            throw err;
          }
        }
      }
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
    <form className={classNames?.method} style={styles.method} onSubmit={submit}>
      <input
        type="email"
        autoComplete="email"
        required
        placeholder="you@example.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        disabled={busy}
        className={classNames?.input}
        style={styles.input}
      />
      {pkGenConfig ? (
        <span className={classNames?.passkeyField} style={styles.passkeyField}>
          <input
            type="password"
            autoComplete="new-password"
            required
            placeholder="passkey"
            value={passkey}
            onChange={(e) => setPasskey(e.target.value)}
            disabled={busy}
            className={classNames?.input}
            // Right padding so typed text never slides under the button. Applied
            // ONLY here, ONLY when the generator is on — the shared `input` slot is
            // untouched so other inputs stay byte-identical.
            style={{ ...styles.input, paddingRight: 48 }}
          />
          <button
            type="button"
            onClick={handleGenerate}
            disabled={busy}
            aria-label="Generate a strong passkey"
            title="Generate a strong passkey"
            className={classNames?.passkeyGenerateButton}
            style={styles.passkeyGenerateButton}
          >
            {pkGenConfig.icon ?? "⚙"}
          </button>
        </span>
      ) : (
        <input
          type="password"
          autoComplete="current-password"
          required
          placeholder="passkey"
          value={passkey}
          onChange={(e) => setPasskey(e.target.value)}
          disabled={busy}
          className={classNames?.input}
          style={styles.input}
        />
      )}
      {revealed ? (
        <div className={classNames?.passkeyReveal} style={styles.passkeyReveal}>
          <span style={{ userSelect: "all" }}>{revealed}</span>
          <span className={classNames?.muted} style={styles.muted}>
            Save this now — it can&apos;t be recovered.
          </span>
          <div className={classNames?.passkeyRevealActions} style={styles.passkeyRevealActions}>
            <button
              type="button"
              onClick={handleCopyReveal}
              className={classNames?.button}
              style={styles.button}
            >
              {copiedFlash ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              onClick={() => setRevealed(null)}
              className={classNames?.button}
              style={styles.button}
            >
              Dismiss
            </button>
          </div>
        </div>
      ) : null}
      <button
        type="submit"
        disabled={busy || !email || !passkey}
        className={classNames?.primaryButton}
        style={styles.primaryButton}
      >
        {icon ? (
          <span className={classNames?.iconWrap} style={styles.iconWrap}>
            {icon}
          </span>
        ) : null}
        {busy ? "…" : "Continue with email"}
      </button>
      {error ? (
        <span className={classNames?.error} style={styles.error}>
          {error}
        </span>
      ) : null}
    </form>
  );
}
