// Browser session storage. SECURITY: the app (encryption) key lives in
// sessionStorage + memory ONLY — never localStorage, never the network.
import type { AuthStatus } from "../core/types.js";

const TOKEN_KEY = "ttc-auth-token";
const PUBKEY_KEY = "ttc-public-key";
const EMAIL_KEY = "user_email";
const EK_KEY = "ttc_ek"; // app/encryption key — sessionStorage only

// In-memory cache so the key survives within a tab without re-reading storage.
let memoryAppKey: string | null = null;

const hasWindow = (): boolean => typeof window !== "undefined";

export function setSession(params: {
  publicKey: string;
  authToken: string;
  appKey: string;
  email?: string;
}): void {
  if (!hasWindow()) return;
  localStorage.setItem(TOKEN_KEY, params.authToken);
  localStorage.setItem(PUBKEY_KEY, params.publicKey);
  if (params.email) localStorage.setItem(EMAIL_KEY, params.email);
  // App key: memory + sessionStorage only.
  memoryAppKey = params.appKey;
  sessionStorage.setItem(EK_KEY, params.appKey);
}

export function getAuthToken(): string | null {
  return hasWindow() ? localStorage.getItem(TOKEN_KEY) : null;
}

export function getPublicKey(): string | null {
  return hasWindow() ? localStorage.getItem(PUBKEY_KEY) : null;
}

export function getEmail(): string | null {
  return hasWindow() ? localStorage.getItem(EMAIL_KEY) : null;
}

/** Retrieve the app/encryption key from memory or sessionStorage. */
export function getAppKey(): string | null {
  if (memoryAppKey) return memoryAppKey;
  if (!hasWindow()) return null;
  memoryAppKey = sessionStorage.getItem(EK_KEY);
  return memoryAppKey;
}

export function clearSession(): void {
  memoryAppKey = null;
  if (!hasWindow()) return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(PUBKEY_KEY);
  localStorage.removeItem(EMAIL_KEY);
  sessionStorage.removeItem(EK_KEY);
}

/**
 * Status model mirroring next-ttc:
 *  - authenticated:    token + public key + app key all present
 *  - session_expired:  account known (token/pubKey) but app key missing (needs re-auth to decrypt)
 *  - unauthenticated:  nothing
 */
export function getAuthStatus(): AuthStatus {
  const hasAccount = !!getAuthToken() && !!getPublicKey();
  if (!hasAccount) return "unauthenticated";
  return getAppKey() ? "authenticated" : "session_expired";
}

/** Headers to attach to authenticated API requests. */
export function authHeaders(): Record<string, string> {
  const token = getAuthToken();
  const pubKey = getPublicKey();
  const headers: Record<string, string> = {};
  if (token) headers["ttc-auth-token"] = token;
  if (pubKey) headers["ttc-public-key"] = pubKey;
  return headers;
}
