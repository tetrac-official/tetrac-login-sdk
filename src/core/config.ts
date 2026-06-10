// Central configuration. Defaults match next-ttc exactly for drop-in compatibility.

export interface KeyPrefixes {
  /** Wallet-login challenge: `${challenge}{pubKey}`. */
  challenge: string;
  /** UserData blob: `${pubKey}{publicKey}`. */
  pubKey: string;
  /** email -> publicKey lookup: `${email}{address}`. */
  email: string;
  /** Rate-limit counters: `${rateLimit}{identifier}`. */
  rateLimit: string;
}

export interface RateLimitConfig {
  windowSeconds: number;
  maxAttempts: number;
}

export interface WebAuthnConfig {
  /** Relying Party ID — must match the site's registrable domain. */
  rpId?: string;
  rpName: string;
  /** Prefer the PRF extension (derive encryption key from authenticator). */
  preferPrf: boolean;
}

export interface AuthConfig {
  /** PBKDF2 iterations for deriving the app key from passkey + email. */
  pbkdf2Iterations: number;
  /** TTL for wallet-login challenges, in seconds. */
  challengeTtlSeconds: number;
  /** Header carrying the opaque session token. */
  sessionHeader: string;
  /** Header carrying the user's public key. */
  publicKeyHeader: string;
  /** TTL applied to issued session tokens, in seconds. Default 86400 (24h). */
  sessionTtlSeconds: number;
  /**
   * When false (default), the server ignores x-forwarded-for / x-real-ip for
   * client-IP derivation — safer default that prevents rate-limit spoofing.
   * Set true only when behind a trusted proxy that sets those headers.
   */
  trustProxyHeaders: boolean;
  keyPrefixes: KeyPrefixes;
  rateLimit: RateLimitConfig;
  webauthn: WebAuthnConfig;
  /**
   * Idle window (ms) before the in-browser app key auto-locks. After it locks,
   * signing throws VaultLockedError and the user must re-authenticate. Default 15s.
   */
  autoLockMs: number;
  /**
   * Where the app key is held while unlocked:
   *  - "session": memory + sessionStorage (survives reload within the tab; default)
   *  - "memory":  memory only (reload ⇒ re-auth; storage-scraping XSS finds nothing)
   */
  appKeyStorage: "session" | "memory";
  /** Lock the vault when the tab becomes hidden. Default true. */
  lockOnHide: boolean;
  /**
   * Revealing a plaintext private key always requires a fresh re-auth ceremony,
   * never the ambient session key. Default true. (Reserved — v1 always re-auths.)
   */
  revealRequiresReauth: boolean;
}

export const DEFAULT_CONFIG: AuthConfig = {
  pbkdf2Iterations: 100_000,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  sessionTtlSeconds: 86_400,
  trustProxyHeaders: false,
  keyPrefixes: {
    challenge: "challenge:",
    pubKey: "pubKey:",
    email: "email:",
    rateLimit: "ratelimit:",
  },
  rateLimit: {
    windowSeconds: 60,
    maxAttempts: 10,
  },
  webauthn: {
    rpName: "TTC",
    preferPrf: true,
  },
  autoLockMs: 15_000,
  appKeyStorage: "session",
  lockOnHide: true,
  revealRequiresReauth: true,
};

/** Merge a partial override onto the defaults (shallow per top-level group). */
export function resolveConfig(override?: DeepPartial<AuthConfig>): AuthConfig {
  if (!override) return DEFAULT_CONFIG;
  return {
    ...DEFAULT_CONFIG,
    ...override,
    keyPrefixes: { ...DEFAULT_CONFIG.keyPrefixes, ...override.keyPrefixes },
    rateLimit: { ...DEFAULT_CONFIG.rateLimit, ...override.rateLimit },
    webauthn: { ...DEFAULT_CONFIG.webauthn, ...override.webauthn },
  } as AuthConfig;
}

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
