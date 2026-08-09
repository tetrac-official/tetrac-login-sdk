// Biometric (Touch ID / Face ID) sub-panel. Mirrors the pattern documented in
// USE_IN_CODE.md §4 — if the caller hands us an existing PasskeyRegistration we
// render "Unlock"; otherwise we register and surface the new registration via
// onPasskeyRegistered so the app can persist it (localStorage / IndexedDB / …).
import React, { useEffect, useState, type CSSProperties } from "react";
// Public subpath import — see EmailMethod.tsx for why we avoid `../react/...`.
import { useAuth } from "@tetrac/login-sdk/react";
import { isBiometricAvailable, PrfUnavailableError } from "../client/webauthn.js";
import type { AuthResult } from "../core/types.js";
import type { PasskeyRegistration } from "../client/webauthn.js";
import type { LoginPanelProps } from "./types.js";

export interface BiometricMethodProps {
  registration: PasskeyRegistration | null | undefined;
  userName: string;
  icon?: React.ReactNode;
  styles: Record<string, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  onSuccess: (result: AuthResult) => void;
  onError: (err: Error) => void;
  onRegistered?: (registration: PasskeyRegistration) => void;
}

export function BiometricMethod({
  registration,
  userName,
  icon,
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
  // Set when the ceremony reveals the authenticator has no PRF extension. The mount
  // probe cannot detect this — isBiometricAvailable() only asks whether a platform
  // authenticator EXISTS (UVPAA), and a device can have Touch ID while lacking PRF.
  // PRF support is reported only in the credential's extension results, so we learn
  // it by attempting, and then retire the option rather than let the user retry into
  // the same failure.
  const [prfUnsupported, setPrfUnsupported] = useState(false);

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
      // PrfUnavailableError is a device capability verdict, not a user mistake — and
      // it is permanent for this authenticator. Retire the option and say something a
      // user can act on, instead of surfacing the developer-facing message verbatim.
      // onError still fires so the host app can steer to email / wallet itself.
      if (e instanceof PrfUnavailableError) setPrfUnsupported(true);
      else setError(e.message);
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  if (available === false || prfUnsupported) {
    return (
      <div className={classNames?.method} style={styles.method}>
        <span className={classNames?.muted} style={styles.muted}>
          {prfUnsupported
            ? "This device can't protect a wallet key with biometrics. Continue with email or a wallet instead."
            : "Biometric not available on this device."}
        </span>
      </div>
    );
  }

  return (
    <div className={classNames?.method} style={styles.method}>
      <button
        type="button"
        onClick={run}
        disabled={busy || available === null}
        className={classNames?.button}
        style={styles.button}
      >
        {icon ? (
          <span className={classNames?.iconWrap} style={styles.iconWrap}>
            {icon}
          </span>
        ) : null}
        {busy ? "…" : registration ? "Unlock with biometric" : "Continue with biometric"}
      </button>
      {error ? (
        <span className={classNames?.error} style={styles.error}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
