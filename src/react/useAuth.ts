// Primary hook: exposes status + bound action wrappers that refresh state.
import { useCallback } from "react";
import { useAuthContext } from "./AuthProvider.js";
import type { AuthResult } from "../core/types.js";
import type { PasskeyRegistration } from "../client/webauthn.js";

export function useAuth() {
  const { client, status, publicKey, email, refresh } = useAuthContext();

  // Wrap each action so React state reflects the new session immediately.
  const wrap = useCallback(
    <Args extends unknown[], R>(fn: (...args: Args) => Promise<R>) =>
      async (...args: Args): Promise<R> => {
        const r = await fn(...args);
        refresh();
        return r;
      },
    [refresh],
  );

  return {
    status,
    publicKey,
    email,
    isAuthenticated: status === "authenticated",
    registerWithEmail: wrap((p: { email: string; passkey: string }) => client.registerWithEmail(p)) as (
      p: { email: string; passkey: string },
    ) => Promise<AuthResult>,
    loginWithEmail: wrap((p: { email: string; passkey: string }) => client.loginWithEmail(p)) as (
      p: { email: string; passkey: string },
    ) => Promise<AuthResult>,
    loginWithWallet: wrap(
      (p: { publicKey: string; signMessage: (m: Uint8Array) => Promise<Uint8Array> }) =>
        client.loginWithWallet(p),
    ),
    connectWallet: wrap(
      (p: { publicKey: string; signMessage: (m: Uint8Array) => Promise<Uint8Array> }) =>
        client.connectWallet(p),
    ),
    registerWithWallet: wrap(
      (p: { publicKey: string; signMessage: (m: Uint8Array) => Promise<Uint8Array> }) =>
        client.registerWithWallet(p),
    ),
    registerWithBiometric: wrap((p: { userName: string }) => client.registerWithBiometric(p)),
    loginWithBiometric: wrap((p: { registration: PasskeyRegistration }) => client.loginWithBiometric(p)),
    logout: useCallback(() => {
      client.logout();
      refresh();
    }, [client, refresh]),
  };
}
