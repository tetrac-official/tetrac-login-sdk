// Biometric (Touch ID / Face ID) sub-panel. Mirrors the pattern documented in
// USE_IN_CODE.md §4 — if the caller hands us an existing PasskeyRegistration we
// render "Unlock"; otherwise we register and surface the new registration via
// onPasskeyRegistered so the app can persist it (localStorage / IndexedDB / …).
import React, { useEffect, useState, type CSSProperties } from "react";
import { useAuth } from "../react/useAuth.js";
import { isBiometricAvailable } from "../client/webauthn.js";
import type { AuthResult } from "../core/types.js";
import type { PasskeyRegistration } from "../client/webauthn.js";
import type { LoginPanelProps } from "./types.js";

export interface BiometricMethodProps {
  registration: PasskeyRegistration | null | undefined;
  userName: string;
  styles: Record<string, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  onSuccess: (result: AuthResult) => void;
  onError: (err: Error) => void;
  onRegistered?: (registration: PasskeyRegistration) => void;
}

export function BiometricMethod({
  registration,
  userName,
  styles,
  classNames,
  onSuccess,
  onError,
  onRegistered,
}: BiometricMethodProps) {
  const { registerWithBiometric, loginWithBiometric } = useAuth();
  const [available, setAvailable] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Feature-detect once on mount; isBiometricAvailable is async (UVPAA probe).
  useEffect(() => {
    let cancelled = false;
    isBiometricAvailable()
      .then((ok) => {
        if (!cancelled) setAvailable(ok);
      })
      .catch(() => {
        if (!cancelled) setAvailable(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function run() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (registration) {
        const result = await loginWithBiometric({ registration });
        onSuccess(result);
      } else {
        const { result, registration: fresh } = await registerWithBiometric({ userName });
        onRegistered?.(fresh);
        onSuccess(result);
      }
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e.message);
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  if (available === false) {
    return (
      <div className={classNames?.method} style={styles.method}>
        <span className={classNames?.methodLabel} style={styles.methodLabel}>
          Biometric
        </span>
        <span className={classNames?.muted} style={styles.muted}>
          Not available on this device.
        </span>
      </div>
    );
  }

  return (
    <div className={classNames?.method} style={styles.method}>
      <span className={classNames?.methodLabel} style={styles.methodLabel}>
        Biometric
      </span>
      <button
        type="button"
        onClick={run}
        disabled={busy || available === null}
        className={classNames?.button}
        style={styles.button}
      >
        {busy
          ? "…"
          : registration
            ? "Unlock with biometric"
            : "Enable biometric login"}
      </button>
      {error ? (
        <span className={classNames?.error} style={styles.error}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
