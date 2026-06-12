// Central configuration. Defaults match next-ttc exactly for drop-in compatibility.

export interface KeyPrefixes {
  /** Wallet-login challenge: `${challenge}{pubKey}`. */
  challenge: string;
  /** UserData blob: `${pubKey}{publicKey}`. */
  pubKey: string;
  /** Session token -> publicKey: `${session}{token}` — disjoint from pubKey so an
   *  attacker-chosen publicKey can never collide with the session-token keyspace. */
  session: string;
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

/** Developer-chosen key-derivation strength. Higher = stronger but slower. */
export type SecurityLevel = 1 | 2 | 3;

/**
 * PBKDF2-HMAC-SHA256 iteration counts per security level, for the email/passkey
 * app-key derivation. Higher = stronger brute-force resistance but slower
 * derivation (more login/unlock latency). The developer picks the level; the
 * resolved iteration COUNT is what gets pinned per-user, so the choice stays
 * stable even if this mapping is retuned later.
 *   1 = 100k   — fastest (~1.2s on M-series); below OWASP 2023, legacy/compat only
 *   2 = 600k   — OWASP 2023 minimum (~7s); recommended default
 *   3 = 1.0M   — future-proof (~12s); highest latency
 * Affects email/passkey accounts only — wallet uses SHA-256(sig), biometric uses PRF.
 */
export const PBKDF2_ITERATIONS: Record<SecurityLevel, number> = {
  1: 100_000,
  2: 600_000,
  3: 1_000_000,
};

export interface AuthConfig {
  /**
   * Key-derivation strength for email/passkey accounts: 1=100k, 2=600k (default),
   * 3=1M PBKDF2-HMAC-SHA256 iterations (see PBKDF2_ITERATIONS). Trades login/unlock
   * latency for brute-force resistance. The resolved iteration COUNT is pinned
   * per-user at registration (UserData.pbkdf2Iterations), so it stays stable for
   * existing accounts even if the default level changes later.
   */
  securityLevel: SecurityLevel;
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
  /**
   * Number of trusted reverse-proxy hops in front of the app. Only consulted when
   * trustProxyHeaders is true: the client IP is taken as the rightmost
   * x-forwarded-for entry AFTER skipping this many hops. Proxies APPEND to XFF on
   * the right, so the rightmost entries are set by infrastructure you control and
   * are not client-spoofable, whereas the leftmost entry is client-supplied.
   *   0 = take the rightmost entry (single trusted edge — e.g. Vercel). DEFAULT.
   *   1 = skip one of your own proxies, etc.
   */
  trustedProxyHops: number;
  keyPrefixes: KeyPrefixes;
  rateLimit: RateLimitConfig;
  webauthn: WebAuthnConfig;
  /**
   * Idle window (ms) before the in-browser app key auto-locks. After it locks,
   * signing throws VaultLockedError and the user must re-authenticate. Default 15s.
   */
  autoLockMs: number;
  /** Lock the vault when the tab becomes hidden. Default true. */
  lockOnHide: boolean;
  /**
   * Revealing a plaintext private key always requires a fresh re-auth ceremony,
   * never the ambient session key. Default true. (Reserved — v1 always re-auths.)
   */
  revealRequiresReauth: boolean;
  /** Max total wallets a single user record may hold — import-wallet cap (record-bloat DoS guard). */
  maxWalletsPerUser: number;
}

export const DEFAULT_CONFIG: AuthConfig = {
  securityLevel: 2,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  sessionTtlSeconds: 86_400,
  trustProxyHeaders: false,
  trustedProxyHops: 0,
  keyPrefixes: {
    challenge: "challenge:",
    pubKey: "pubKey:",
    session: "session:",
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
  lockOnHide: true,
  revealRequiresReauth: true,
  maxWalletsPerUser: 64,
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
