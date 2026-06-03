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
  keyPrefixes: KeyPrefixes;
  rateLimit: RateLimitConfig;
  webauthn: WebAuthnConfig;
}

export const DEFAULT_CONFIG: AuthConfig = {
  pbkdf2Iterations: 100_000,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
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
