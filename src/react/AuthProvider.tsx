// React context that wraps an AuthClient and tracks auth status + user data.
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AuthClient, type AuthClientOptions } from "../client/authClient.js";
import { getAuthStatus, getPublicKey, getEmail } from "../client/session.js";
import type { AuthStatus, UserData } from "../core/types.js";

export interface AuthContextValue {
  client: AuthClient;
  status: AuthStatus;
  publicKey: string | null;
  email: string | null;
  /** Re-read status from storage (call after a custom flow mutates the session). */
  refresh: () => void;
  /** Cached user record (encrypted wallets + identity). Null until the first fetch resolves. */
  user: UserData | null;
  /** True while a user-data fetch is in flight. */
  userLoading: boolean;
  /** Force a fresh user-data fetch (e.g. after importing a wallet). */
  refetchUser: () => Promise<void>;
  /**
   * Address of an externally connected Solana wallet (Phantom/Backpack/etc.).
   * Passed in via the <AuthProvider externalSolanaAddress=…> prop. The SDK
   * doesn't subscribe to @solana/wallet-adapter-react itself — the app pipes it in.
   */
  externalSolanaAddress: string | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps extends AuthClientOptions {
  children: React.ReactNode;
  /**
   * Address of an externally connected Solana wallet. When set, useActiveWallet()
   * returns this in place of the embedded funds wallet (the "external connected wins"
   * rule). Set to null/undefined when no external wallet is connected.
   */
  externalSolanaAddress?: string | null;
}

export function AuthProvider({ children, externalSolanaAddress = null, ...options }: AuthProviderProps) {
  // Stable client across renders; options are read once on mount.
  const client = useMemo(() => new AuthClient(options), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [status, setStatus] = useState<AuthStatus>("unauthenticated");
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [user, setUser] = useState<UserData | null>(null);
  const [userLoading, setUserLoading] = useState(false);

  const refresh = useCallback(() => {
    setStatus(getAuthStatus());
    setPublicKey(getPublicKey());
    setEmail(getEmail());
  }, []);

  // Track in-flight fetches so a stale response can't overwrite a newer one.
  const fetchSeq = useRef(0);

  const refetchUser = useCallback(async () => {
    const mySeq = ++fetchSeq.current;
    setUserLoading(true);
    try {
      const fresh = await client.fetchUserData();
      if (mySeq === fetchSeq.current) setUser(fresh);
    } finally {
      if (mySeq === fetchSeq.current) setUserLoading(false);
    }
  }, [client]);

  // Hydrate from storage on mount (client-only).
  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-fetch user-data when authenticated, clear when not.
  useEffect(() => {
    if (status === "authenticated") {
      void refetchUser();
    } else {
      // Bump seq so any in-flight fetch is ignored on resolution.
      fetchSeq.current++;
      setUser(null);
      setUserLoading(false);
    }
  }, [status, publicKey, refetchUser]);

  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      status,
      publicKey,
      email,
      refresh,
      user,
      userLoading,
      refetchUser,
      externalSolanaAddress,
    }),
    [client, status, publicKey, email, refresh, user, userLoading, refetchUser, externalSolanaAddress],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
