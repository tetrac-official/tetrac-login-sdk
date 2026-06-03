// React context that wraps an AuthClient and tracks auth status.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { AuthClient, type AuthClientOptions } from "../client/authClient.js";
import { getAuthStatus, getPublicKey, getEmail } from "../client/session.js";
import type { AuthStatus } from "../core/types.js";

export interface AuthContextValue {
  client: AuthClient;
  status: AuthStatus;
  publicKey: string | null;
  email: string | null;
  /** Re-read status from storage (call after a custom flow mutates the session). */
  refresh: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps extends AuthClientOptions {
  children: React.ReactNode;
}

export function AuthProvider({ children, ...options }: AuthProviderProps) {
  // Stable client across renders; options are read once on mount.
  const client = useMemo(() => new AuthClient(options), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [status, setStatus] = useState<AuthStatus>("unauthenticated");
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setStatus(getAuthStatus());
    setPublicKey(getPublicKey());
    setEmail(getEmail());
  }, []);

  // Hydrate from storage on mount (client-only).
  useEffect(() => {
    refresh();
  }, [refresh]);

  const value = useMemo<AuthContextValue>(
    () => ({ client, status, publicKey, email, refresh }),
    [client, status, publicKey, email, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
