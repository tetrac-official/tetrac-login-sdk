// Central configuration. Defaults match next-ttc exactly for drop-in compatibility.

export interface KeyPrefixes {
  /** Wallet-login challenge: `${challenge}{appId}:{pubKey}` (app-scoped, v0.4.0). */
  challenge: string;
  /** UserData blob: `${pubKey}{appId}:{publicKey}` (app-scoped, v0.4.0). */
  pubKey: string;
  /** Session token -> publicKey: `${session}{appId}:{token}` (app-scoped, v0.4.0) —
   *  disjoint from pubKey so an attacker-chosen publicKey can never collide with the
   *  session-token keyspace, and a token minted by one app is never honored by another. */
  session: string;
  /** email -> { [appId]: publicKey } hash: `${email}{address}`. The KEY is NOT
   *  app-scoped — a single email maps to a per-app public key under each appId field,
   *  so one shared DB can answer "which apps does this email use?" (v0.4.0). */
  email: string;
  /** Rate-limit counters: `${rateLimit}{endpoint}:{appId}:{identifier}` (app-scoped, v0.4.0). */
  rateLimit: string;
}

/**
 * The wire header names, as CONSTANTS rather than config.
 *
 * They were once configurable — `AuthConfig.sessionHeader` / `publicKeyHeader` /
 * `appIdHeader` — and the server honoured them while the client hardcoded the same three
 * strings. Setting one therefore broke authentication silently: the server looked for the
 * configured name, the client sent the literal, and every authenticated request returned
 * 401 with nothing to indicate why. Two sources of truth for one wire contract.
 *
 * A single exported constant cannot drift. It is also the better documentation — importable
 * by a wrapper route, a proxy allowlist, or a test, instead of a re-typed string literal.
 */
/** Carries the opaque session token. */
export const AUTH_TOKEN_HEADER = "ttc-auth-token";
/** Carries the user's public key. */
export const PUBLIC_KEY_HEADER = "ttc-public-key";
/** Carries the request's appId on authenticated routes; falls back to config.appId. */
export const APP_ID_HEADER = "ttc-app-id";

export interface RateLimitConfig {
  windowSeconds: number;
  maxAttempts: number;
}

export interface WebAuthnConfig {
  /** Relying Party ID — must match the site's registrable domain. */
  rpId?: string;
  rpName: string;
  // NOTE: there is no PRF opt-out. The WebAuthn PRF extension is required for every
  // biometric flow; an authenticator without it throws PrfUnavailableError. Serving
  // such a device would mean storing a secret the page can read — i.e. one any script
  // on the origin can read — which is not a weaker tier of the guarantee but its
  // absence. Those users get email + passkey or a Web3 wallet instead.
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
   *
   * Since v0.4.0 `appId` is ALSO the server-side storage namespace and the
   * single-app fallback: a request may carry its own `appId` (body field or
   * `appIdHeader`), and when it doesn't, this value is used. Every per-user key
   * (`pubKey:`, `challenge:`, `session:`, rate-limit) is scoped by the resolved
   * appId, so multiple apps can safely share one Redis/Upstash database.
   */
  appId: string;
  /**
   * The deployment's canonical origin, e.g. `"https://myapp.example"` — scheme + host
   * (+ port), no path, no trailing slash.
   *
   * REQUIRED for every Web3 wallet route;
   */
  origin: string;
  /**
   * Optional allowlist of accepted `appId` values (v0.4.0). When set, a request
   * carrying any other appId is rejected (`Unknown appId`). Leave undefined to
   * accept any well-formed appId (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`). STRONGLY
   * recommended in production for a shared DB, so an attacker cannot mint arbitrary
   * namespaces (storage-bloat) or probe tenants by guessing ids.
   */
  allowedAppIds?: string[];
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
  /** TTL applied to issued session tokens, in seconds. Default 86400 (24h). The TTL is the
   *  backstop, not the primary revocation path: each new login revokes the prior token, so
   *  a leaked bearer token dies at the owner's next sign-in rather than at expiry. */
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
  /**
   * The GLOBAL per-IP bucket, checked on every rate-limited route and keyed on the client
   * IP alone — no endpoint, no appId. Default **100 per 60s**.
   *
   * It is deliberately its own config, NOT `rateLimit` (audit 2026-08-08 F-7). `rateLimit`
   * sizes PER-ENDPOINT, PER-IDENTIFIER buckets; this one AGGREGATES every request from an
   * address. Reusing `rateLimit`'s 10/60s here meant one egress IP supported only ~2
   * sign-ins per minute (an "auto" email sign-in is up to four counted requests), which is
   * fine for a residential IP and wrong for the population that shares one: corporate and
   * university NAT, carrier-grade NAT, VPN exit nodes. Size this above
   * `requests-per-sign-in × expected concurrent users per egress IP`; it is still a strong
   * abuse signal (100/60s ≈ 25 concurrent sign-ins from one NAT) while not throttling
   * shared-IP users during normal use.
   */
  ipRateLimit: RateLimitConfig;
  /**
   * Ceiling on ACCOUNT CREATION for the whole deployment. Default **2 per 60s**.
   *
   * This is the one bucket that is not keyed on anything the caller supplies. Every other
   * bucket is keyed on an email or a public key taken from the request body, so an
   * attacker rotating either gets a fresh counter and the limit never fires — which is how
   * an anonymous client creates unbounded permanent records. A single global counter has
   * no key to rotate.
   *
   * Charged ONLY when a record is actually created — not on every `/register` hit. The
   * client's "auto" mode registers first and falls back to login on 409, so returning
   * users hit `/register` routinely; counting those would throttle ordinary logins.
   *
   * SIZE THIS FROM YOUR SIGNUP VOLUME. It is a capacity number, not a security dial. If a
   * launch does 200 signups an hour, 2/min is comfortable; if it does 200 in five minutes,
   * this will reject real users, who then see a 429 and must retry. That failure is
   * recoverable — nobody is locked out of an existing account — but it is still a failure.
   */
  accountCreationRateLimit: RateLimitConfig;
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
}

/**
 * Defaults for everything EXCEPT `origin`, which has no safe default: on a server there
 * is nothing to infer it from, and inventing one (localhost, the request's Host header)
 * would silently un-bind every wallet signature. resolveConfig supplies it from
 * `window.location.origin` in a browser and demands it explicitly everywhere else.
 */
export const DEFAULT_CONFIG: Omit<AuthConfig, "origin"> = {
  appId: "ttc", // override per-deployment for cross-app key isolation (see AuthConfig.appId)
  securityLevel: 2,
  challengeTtlSeconds: 300,
  sessionTtlSeconds: 86_400,
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
  ipRateLimit: {
    windowSeconds: 60,
    maxAttempts: 100,
  },
  accountCreationRateLimit: {
    windowSeconds: 60,
    maxAttempts: 2,
  },
  webauthn: {
    rpName: "TTC",
  },
  autoLockMs: 15_000,
  lockOnHide: true,
  revealRequiresReauth: true,
};

/**
 * Normalize an origin for message building and comparison: lowercase, no trailing
 * slash. `window.location.origin` and a hand-written config value must produce the
 * same bytes or every wallet login fails, so both sides route through this.
 */
export function normalizeOrigin(origin: string): string {
  return origin.trim().toLowerCase().replace(/\/+$/, "");
}

/** `window.location.origin` when running in a browser, else undefined. */
function browserOrigin(): string | undefined {
  return typeof window !== "undefined" ? window.location?.origin : undefined;
}

/**
 * Merge a partial override onto the defaults (shallow per top-level group).
 *
 * `origin` is mandatory in the resolved config. In a browser it defaults to the page's
 * REAL `window.location.origin`; on a server it must be given explicitly, and resolving
 * without it throws rather than producing a config whose wallet signatures verify
 * against nothing in particular.
 */
export function resolveConfig(override?: DeepPartial<AuthConfig>): AuthConfig {
  const origin = override?.origin ?? browserOrigin();
  if (!origin) {
    throw new Error(
      "[tetrac] config.origin is required. Set it to this deployment's canonical origin " +
        "(e.g. 'https://myapp.example'). It binds wallet signatures to your site so they " +
        "cannot be relayed from another, and it is app-key derivation input — set it once " +
        "and never change it, or existing encrypted wallets will not decrypt.",
    );
  }
  return {
    ...DEFAULT_CONFIG,
    ...override,
    origin: normalizeOrigin(origin),
    keyPrefixes: { ...DEFAULT_CONFIG.keyPrefixes, ...override?.keyPrefixes },
    rateLimit: { ...DEFAULT_CONFIG.rateLimit, ...override?.rateLimit },
    ipRateLimit: { ...DEFAULT_CONFIG.ipRateLimit, ...override?.ipRateLimit },
    accountCreationRateLimit: {
      ...DEFAULT_CONFIG.accountCreationRateLimit,
      ...override?.accountCreationRateLimit,
    },
    webauthn: { ...DEFAULT_CONFIG.webauthn, ...override?.webauthn },
  } as AuthConfig;
}

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
