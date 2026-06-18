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
   * Stable, per-deployment application identifier that DOMAIN-SEPARATES app-key
   * derivation. It is mixed into the PBKDF2 salt for email/passkey accounts
   * (`salt = SHA-256(appId : email)`) and into the message a Web3 wallet signs to
   * derive its key — so the SAME (email+passkey) or the SAME wallet derives a
   * DIFFERENT app key per app. This prevents cross-app key reuse (a key cracked or
   * coerced on one app can't unlock the same user on another) and stops a single
   * precomputed table from working across every deployment.
   *
   * MUST be unique and STABLE per deployment: set it once to something like your
   * product/domain (e.g. "myapp.example"). Changing it re-derives every app key, so
   * existing encrypted wallets would no longer decrypt. The default "ttc" works out
   * of the box but provides NO cross-app isolation — override it in production.
   */
  appId: string;
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
  /** TTL applied to issued session tokens, in seconds. Default 14400 (4h) — a leaked
   *  bearer token dies sooner. Each new login also revokes the prior token. */
  sessionTtlSeconds: number;
  /**
   * Optionally bind each session to a coarse fingerprint of the request `User-Agent`
   * (`SHA-256(ua)`), checked on every authenticated request. Default **false**.
   *
   * Defense-in-depth only: it raises the bar for using a stolen bearer token from a
   * different client, but the UA is attacker-spoofable and not a real device identity,
   * so treat it as a speed bump, not a control. TRADE-OFF: a legitimate UA change
   * (browser auto-update, app upgrade) invalidates the session and forces re-login.
   * Enforcement is per-session — turning this on binds only sessions issued afterward;
   * a bound session stays enforced until it expires even if the flag is later disabled.
   */
  bindSessionToUserAgent: boolean;
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
  appId: "ttc", // override per-deployment for cross-app key isolation (see AuthConfig.appId)
  securityLevel: 2,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  sessionTtlSeconds: 14_400,
  bindSessionToUserAgent: false,
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
