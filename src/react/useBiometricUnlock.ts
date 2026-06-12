// Optional biometric-UNLOCK hook for ANY account. See PRD §3.3.
//
// This is the convenience wrapper around the client biometricUnlock functions.
// enable() wraps the CURRENT app key under a freshly-registered passkey (vault
// must be unlocked); unlock() re-arms the vault via Touch ID; disable() purges
// the on-device state.
//
// PERSISTENCE: enable() returns a PasskeyRegistration that unlock()/disable()
// need, but the hook's unlock()/disable() take no args — so the hook persists
// the registration itself in localStorage. The registration is NON-SECRET
// ({ credentialId, salt, rpId, mode }); the only secret-bearing artifact is the
// wrapped blob in IndexedDB, which is useless without a fresh assertion.
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuthContext } from "./AuthProvider.js";
import {
  isBiometricAvailable,
  hasBiometricUnlock,
  type PasskeyRegistration,
} from "../client/index.js";

// Non-secret registration descriptor, persisted so unlock()/disable() need no args.
const REG_KEY = "ttc_biometric_reg";

const hasWindow = (): boolean => typeof window !== "undefined";

function loadReg(): PasskeyRegistration | null {
  if (!hasWindow()) return null;
  const raw = localStorage.getItem(REG_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PasskeyRegistration;
  } catch {
    return null;
  }
}

function saveReg(reg: PasskeyRegistration): void {
  if (hasWindow()) localStorage.setItem(REG_KEY, JSON.stringify(reg));
}

function clearReg(): void {
  if (hasWindow()) localStorage.removeItem(REG_KEY);
}

export interface UseBiometricUnlockResult {
  /** Platform exposes WebAuthn + a platform (biometric) authenticator. Async-resolved. */
  available: boolean;
  /** A biometric-unlock blob is registered on this device. */
  isEnabled: boolean;
  /** Wrap the current app key under a fresh passkey (vault must be unlocked). */
  enable: (userName?: string) => Promise<void>;
  /** Remove the on-device biometric-unlock state. */
  disable: () => Promise<void>;
  /** Re-arm the vault via Touch ID (unwrap the stored app key). */
  unlock: () => Promise<void>;
  /** True while enable/disable/unlock is in flight. */
  loading: boolean;
  /** Error from the last action, or null. */
  error: Error | null;
}

export function useBiometricUnlock(): UseBiometricUnlockResult {
  const { client, refresh } = useAuthContext();
  const [available, setAvailable] = useState(false);
  const [isEnabled, setIsEnabled] = useState<boolean>(() => hasBiometricUnlock());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const mounted = useRef(true);

  // isBiometricAvailable() is async — resolve it once on mount.
  useEffect(() => {
    mounted.current = true;
    void isBiometricAvailable().then((ok) => {
      if (mounted.current) setAvailable(ok);
    });
    // Sync the enabled flag in case it changed before mount (e.g. logout purge).
    setIsEnabled(hasBiometricUnlock());
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (fn: () => Promise<void>): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      if (mounted.current) setError(err);
      throw err;
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, []);

  const enable = useCallback(
    (userName?: string) =>
      run(async () => {
        // Persist the returned (non-secret) registration so unlock/disable work argless.
        const reg = await client.enableBiometricUnlock(userName ?? "biometric-unlock");
        saveReg(reg);
        if (mounted.current) setIsEnabled(true);
      }),
    [client, run],
  );

  const disable = useCallback(
    () =>
      run(async () => {
        const reg = loadReg();
        if (reg) await client.disableBiometricUnlock(reg);
        clearReg();
        if (mounted.current) setIsEnabled(false);
      }),
    [client, run],
  );

  const unlock = useCallback(
    () =>
      run(async () => {
        const reg = loadReg();
        if (!reg) throw new Error("No biometric unlock is registered on this device");
        await client.unlockViaBiometric(reg);
        // Re-arm happened inside the client — refresh AuthProvider status.
        refresh();
      }),
    [client, run, refresh],
  );

  return { available, isEnabled, enable, disable, unlock, loading, error };
}
