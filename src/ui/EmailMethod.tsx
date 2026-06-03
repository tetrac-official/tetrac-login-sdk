// Email + passkey sub-panel. Wraps useAuth().{registerWithEmail,loginWithEmail}
// and implements the "auto" mode documented in USE_IN_CODE.md §4 (try register,
// fall back to login on 409).
import React, { useState, type CSSProperties } from "react";
// Import via the public subpath, not a relative path: a relative import causes
// tsup to inline `useAuth` + `AuthContext` into dist/ui/index.js, producing a
// second AuthContext instance that <AuthProvider> never populates. Treating the
// react subpath as external preserves a single shared context at runtime.
import { useAuth } from "@tetrac/login-sdk/react";
import type { AuthResult } from "../core/types.js";
import type { LoginPanelProps } from "./types.js";

export interface EmailMethodProps {
  mode: NonNullable<LoginPanelProps["emailMode"]>;
  styles: Record<string, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  onSuccess: (result: AuthResult) => void;
  onError: (err: Error) => void;
}

export function EmailMethod({ mode, styles, classNames, onSuccess, onError }: EmailMethodProps) {
  const { registerWithEmail, loginWithEmail } = useAuth();
  const [email, setEmail] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      <span className={classNames?.methodLabel} style={styles.methodLabel}>
        Email
      </span>
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
      <button
        type="submit"
        disabled={busy || !email || !passkey}
        className={classNames?.primaryButton}
        style={styles.primaryButton}
      >
        {busy ? "…" : "Continue"}
      </button>
      {error ? (
        <span className={classNames?.error} style={styles.error}>
          {error}
        </span>
      ) : null}
    </form>
  );
}
