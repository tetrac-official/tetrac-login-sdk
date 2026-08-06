// Framework-agnostic auth route handlers built on the Web Request/Response API.
// Next.js App Router consumes these directly via src/next.
import type { StorageAdapter } from "../storage/adapter.js";
import { KvAuthStore, type AuthStore, type RateLimitBucket } from "../storage/store.js";
import {
  resolveConfig,
  APP_ID_HEADER,
  AUTH_TOKEN_HEADER,
  PUBLIC_KEY_HEADER,
  type AuthConfig,
  type DeepPartial,
} from "../core/config.js";
import {
  WALLET_SLOTS,
  type AuthResult,
  type EncryptedWallet,
  type OffchainEnvelope,
  type UserData,
} from "../core/types.js";
import { PublicKey } from "@solana/web3.js";
import { json, error, clientIp, readJson } from "./http.js";
import { hashUserAgent } from "../core/crypto.js";
import { checkRateLimit } from "./rateLimit.js";
import { issueChallenge, consumeChallenge } from "./challenge.js";
import { verifySolanaSignature, verifyAuthSignature } from "./signature.js";
import {
  persistUser,
  getUserByPublicKey,
  resolvePublicKeyByEmail,
  issueSession,
  verifySession,
  revokeSession,
} from "./session.js";

/**
 * Supply EITHER `store` (an AuthStore — the domain port, and what a real database should
 * implement) OR `storage` (a Redis-shaped StorageAdapter, which is wrapped automatically).
 *
 * `storage` remains fully supported: every existing deployment keeps working untouched.
 */
export interface AuthHandlerOptions {
  /** A Redis-family KV backend. Wrapped in a KvAuthStore for you. */
  storage?: StorageAdapter;
  /** A native domain backend. Takes precedence over `storage` when both are given. */
  store?: AuthStore;
  config?: DeepPartial<AuthConfig>;
}

export interface AuthHandlers {
  config: AuthConfig;
  challenge(req: Request): Promise<Response>;
  register(req: Request): Promise<Response>;
  login(req: Request): Promise<Response>;
  loginWallet(req: Request): Promise<Response>;
  connectWallet(req: Request): Promise<Response>;
  logout(req: Request): Promise<Response>;
  userData(req: Request): Promise<Response>;
  searchWallet(req: Request): Promise<Response>;
  importWallet(req: Request): Promise<Response>;
}

// --- request input validators (v0.2.1 Change 4) ---
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX64_RE = /^[0-9a-f]{64}$/i;
// appId is now attacker-influenced (request body / header), and it is concatenated
// into Redis keys, so it must be validated BEFORE it ever reaches a key (v0.4.0).
// The charset forbids ':' (the key-namespace separator) and whitespace, and bounds
// the length, so a crafted appId can neither escape its namespace nor bloat keys.
const APP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function validateEmail(email: string): string | null {
  if (email.length > 320 || !EMAIL_RE.test(email)) return "Invalid email format";
  return null;
}

function validateAppId(appId: string, config: AuthConfig): string | null {
  if (!appId || !APP_ID_RE.test(appId)) return "Invalid appId format";
  // Optional production allowlist: reject any appId the deployment didn't declare,
  // so an attacker can't mint arbitrary namespaces or probe tenants by guessing ids.
  if (config.allowedAppIds && !config.allowedAppIds.includes(appId)) return "Unknown appId";
  return null;
}

function validatePublicKey(key: string): string | null {
  // The account identity is a Solana ed25519 public key (generated client-side for
  // email/biometric, or the connected wallet for web3). Require base58 that decodes to
  // exactly 32 bytes in CANONICAL form: PublicKey throws on invalid base58 / wrong
  // length, the round-trip rejects short inputs PublicKey would left-pad, and EVM
  // `0x…` addresses fail because `0` isn't in the base58 alphabet.
  if (!key) return "Invalid publicKey format";
  try {
    const pk = new PublicKey(key);
    if (pk.toBytes().length !== 32 || pk.toBase58() !== key) return "Invalid publicKey format";
  } catch {
    return "Invalid publicKey format";
  }
  return null;
}

function validateAuthPublicKey(key: string): string | null {
  if (!HEX64_RE.test(key)) return "Invalid authPublicKey format"; // ed25519 public key, 32 bytes hex
  return null;
}

// PBKDF2 iteration bounds the server pins per-user. The client picks securityLevel
// (1/2/3 -> 100k/600k/1M), but the server must not trust the count blindly (audit F3):
// a malicious/buggy client could pin `1` and kneecap that account's brute-force
// resistance. Floor = the documented level-1 (legacy) minimum; ceiling = level-3.
const PBKDF2_MIN = 100_000;
const PBKDF2_MAX = 1_000_000;
/** The off-chain envelope pinned on a hardware account. Derivation input — validate it. */
function validEnvelope(v: unknown): v is OffchainEnvelope {
  return v === "legacy" || v === "v0";
}

function validIterations(n: unknown): boolean {
  return typeof n === "number" && Number.isInteger(n) && n >= PBKDF2_MIN && n <= PBKDF2_MAX;
}

export function createAuthHandlers(opts: AuthHandlerOptions): AuthHandlers {
  const config = resolveConfig(opts.config);
  // A native AuthStore wins; otherwise wrap the KV adapter. One of the two is required.
  const store: AuthStore =
    opts.store ??
    (opts.storage
      ? new KvAuthStore(opts.storage, config.keyPrefixes)
      : (() => {
          throw new Error(
            "[tetrac] createAuthHandlers requires either `store` (AuthStore) or `storage` (StorageAdapter).",
          );
        })());

  // Apply rate limiting; returns a 429 Response or null. We only gate on the
  // client IP when we actually have a trustworthy one (trustProxyHeaders behind a
  // real proxy); otherwise clientIp() is the constant "unknown" and gating on it
  // would be a GLOBAL lockout vector — one abuser would lock out everyone — so we
  // skip it and rely on the per-target bucket below (H5). Every rate-limited endpoint
  // passes a per-target bucket, so nothing is left unprotected when the IP leg is
  // skipped. Buckets are ENDPOINT-SCOPED so one endpoint's limit can never bleed into
  // and lock a victim out of a DIFFERENT endpoint they need — e.g. failed logins must
  // not exhaust the bucket the victim's /challenge uses.
  //
  // The IP bucket carries no appId on purpose: it is global across endpoints and apps,
  // so one abusive IP is throttled everywhere at once.
  async function rateLimited(req: Request, bucket?: RateLimitBucket): Promise<Response | null> {
    if (config.trustProxyHeaders) {
      const ip = await checkRateLimit(
        store,
        { endpoint: "ip", identifier: clientIp(req, true, config.trustedProxyHops) },
        config.rateLimit,
      );
      if (!ip.allowed) return error("Rate limit exceeded", 429);
    }
    if (bucket) {
      const id = await checkRateLimit(store, bucket, config.rateLimit);
      if (!id.allowed) return error("Rate limit exceeded", 429);
    }
    return null;
  }

  // The deployment-wide ceiling on NEW ACCOUNTS. One bucket: no appId, no identifier.
  //
  // That is the entire point. Every other bucket is keyed on an email or a public key
  // lifted from the request body, so an attacker who generates a fresh keypair per request
  // gets a fresh counter and the limit never fires — which is how an anonymous client
  // creates unbounded, permanent, un-swept records. There is no key here to rotate.
  //
  // It is NOT app-scoped either: `appId` also comes from the request, so scoping by it
  // would hand back the same rotation (unless allowedAppIds is set, which it is not by
  // default).
  //
  // CALL THIS ONLY WHERE A RECORD IS ACTUALLY CREATED. The client's "auto" mode registers
  // first and falls back to login on 409, so returning users hit /register on every normal
  // sign-in; charging them would turn a 2/min creation ceiling into a 2/min login ceiling.
  async function accountCreationLimited(): Promise<Response | null> {
    const r = await checkRateLimit(
      store,
      { endpoint: "create", identifier: "global" },
      config.accountCreationRateLimit,
    );
    return r.allowed ? null : error("Too many new accounts right now — try again shortly", 429);
  }

  // Every wallet signature is verified against config.origin — SERVER config, never the
  // request. Echoing a client-supplied origin back into the message would reinstate
  // exactly the relay attack the binding exists to prevent. resolveConfig guarantees the
  // value is present (it throws otherwise), so there is no unbound-verification path to
  // fall back to.

  // Optional coarse session→User-Agent binding (config.bindSessionToUserAgent,
  // default off). At ISSUE time we fingerprint only when the flag is on; at VERIFY
  // time we always compute the request fingerprint and let verifySession enforce it
  // iff the session was bound — so flipping the flag off never un-binds live sessions.
  function issueFingerprint(req: Request): string | undefined {
    return config.bindSessionToUserAgent ? hashUserAgent(req.headers.get("user-agent")) : undefined;
  }
  function reqFingerprint(req: Request): string | undefined {
    return hashUserAgent(req.headers.get("user-agent"));
  }

  // Resolve the request's appId on authenticated routes from APP_ID_HEADER, falling
  // back to config.appId for single-app deployments. Returns null when the supplied
  // value is malformed (e.g. contains the ':' key separator) so the caller can fail
  // closed (401) rather than build a key from attacker-controlled input (v0.4.0).
  function headerAppId(req: Request): string | null {
    const appId = req.headers.get(APP_ID_HEADER) ?? config.appId;
    return validateAppId(appId, config) ? null : appId;
  }

  // Client-safe copy of a user record. `authTokenHash` is the session identifier (not a
  // credential — it is a SHA-256 digest), but the client has no use for it, so it never
  // leaves the server. `authToken` is the pre-v0.5.0 raw-token field: still stripped,
  // because a record written by an older version may carry one until its next write.
  // authPublicKey IS public key material, so it stays.
  function publicUser(user: UserData): UserData {
    const { authToken: _authToken, authTokenHash: _authTokenHash, ...safe } = user;
    return safe as UserData;
  }

  // The raw token is passed in explicitly rather than read back off `user`. Before
  // v0.5.0 issueSession mutated `user.authToken` and this read it from there — a
  // side-channel that only worked because the raw token was persisted. It no longer is.
  function asResult(user: UserData, token: string): AuthResult {
    return { publicKey: user.publicKey, authToken: token, user: publicUser(user) };
  }

  // Validate a client-supplied wallets[] payload. Returns an error Response (400) or null
  // when the array is acceptable.
  //
  // A user record holds AT MOST ONE wallet per (chain, role) — four slots, no more (see
  // WALLET_SLOTS). That bound is what keeps the encrypted blob a fixed-size object instead
  // of an append-only list, and it is enforced here rather than by a numeric cap: a request
  // carrying two entries for the same slot is malformed, not merely large.
  function readWallets(wallets: unknown): { error: Response } | { wallets: EncryptedWallet[] } {
    if (!Array.isArray(wallets)) return { error: error("wallets must be an array") };
    if (wallets.length > WALLET_SLOTS.length) return { error: error("too many wallets") };
    const seen = new Set<string>();
    const clean: EncryptedWallet[] = [];
    for (const w of wallets) {
      if (!w || typeof w !== "object") return { error: error("invalid wallet entry") };
      const e = w as Record<string, unknown>;
      if (typeof e.publicKey !== "string" || typeof e.encryptedSecret !== "string") {
        return { error: error("invalid wallet entry") };
      }
      if (e.publicKey.length > 128) return { error: error("wallet publicKey too long") };
      if (e.role !== "funds" && e.role !== "signing") return { error: error("invalid wallet entry") };
      if (e.chain !== "solana" && e.chain !== "evm") return { error: error("invalid wallet entry") };
      if (e.encryptedSecret.length > 8192) return { error: error("encryptedSecret too large") };
      const slot = `${e.chain}:${e.role}`;
      if (seen.has(slot)) return { error: error("duplicate wallet slot") };
      seen.add(slot);
      // REBUILD from an allowlist — never persist the caller's object.
      //
      // Validating the known fields and then storing what arrived is not the same thing.
      // Unknown properties were carried through verbatim into JSON.stringify(user), so a
      // single anonymous /register carrying `{chain, role, publicKey, encryptedSecret,
      // junk: "x".repeat(5_000_000)}` persisted 5 MB — every bound above satisfied. The
      // four fields below are the entire wire contract; anything else is dropped here,
      // which makes the stored size a function of the bounds rather than of the caller.
      clean.push({
        chain: e.chain,
        role: e.role,
        publicKey: e.publicKey,
        encryptedSecret: e.encryptedSecret,
      });
    }
    return { wallets: clean };
  }

  return {
    config,

    async challenge(req) {
      const body = await readJson<{ appId?: string; publicKey?: string; email?: string }>(req);
      const appId = body?.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      if (body?.publicKey) {
        const e = validatePublicKey(body.publicKey);
        if (e) return error(e);
      }
      if (body?.email) {
        const e = validateEmail(body.email);
        if (e) return error(e);
      }
      // Rate-limit BEFORE resolving/issuing, keyed on the client-supplied identifier
      // (publicKey for the wallet flow, email for the email/biometric flow). Doing it
      // here — rather than after resolution — means the IP bucket (when trusted) and
      // the per-target bucket also throttle probes for UNKNOWN emails; otherwise an
      // unknown email escapes limiting entirely and the 200-vs-400 response becomes an
      // unbounded enumeration oracle. Per-target keying still avoids the global "unknown"
      // lockout (H5); the residual per-target DoS is the developer's edge to own.
      const identifier = body?.publicKey ?? body?.email;
      if (identifier) {
        const limited = await rateLimited(req, { endpoint: "challenge", appId, identifier });
        if (limited) return limited;
      }
      // Wallet flow passes publicKey; email/biometric flow passes the account email
      // (or internal biometric id), which we resolve to the identity publicKey.
      let publicKey = body?.publicKey ?? null;
      if (!publicKey && body?.email) {
        publicKey = await resolvePublicKeyByEmail(store, appId, body.email);
      }
      if (!publicKey) return error("publicKey or email required");
      const challenge = await issueChallenge(store, appId, publicKey, config);
      // Accounts also need their PINNED derivation parameters back before they can sign:
      // the PBKDF2 iteration count (email) and the off-chain envelope (hardware wallet).
      // Both are app-key derivation input and neither is secret. Re-deriving with a
      // different value silently yields a different key and undecryptable wallets.
      const user = await getUserByPublicKey(store, appId, publicKey);
      return json({
        challenge,
        pbkdf2Iterations: user?.pbkdf2Iterations,
        offchainEnvelope: user?.offchainEnvelope,
      });
    },

    async register(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        email?: string;
        authPublicKey?: string;
        authMethod?: UserData["authMethod"];
        wallets?: EncryptedWallet[];
        signature?: string;
        challenge?: string;
        pbkdf2Iterations?: number;
        offchainEnvelope?: OffchainEnvelope;
      }>(req);
      if (!body?.publicKey) return error("publicKey required");
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);
      if (body.email) {
        const emailErr = validateEmail(body.email);
        if (emailErr) return error(emailErr);
      }
      if (body.authPublicKey) {
        const apErr = validateAuthPublicKey(body.authPublicKey);
        if (apErr) return error(apErr);
      }
      let wallets: EncryptedWallet[] = [];
      if (body.wallets !== undefined) {
        const r = readWallets(body.wallets);
        if ("error" in r) return r.error;
        wallets = r.wallets;
      }
      // Reject a client-supplied PBKDF2 count outside the allowed band (audit F3).
      // Absent is fine — legacy/wallet accounts don't pin one.
      if (body.pbkdf2Iterations != null && !validIterations(body.pbkdf2Iterations)) {
        return error("Invalid pbkdf2Iterations", 400);
      }
      if (body.offchainEnvelope != null && !validEnvelope(body.offchainEnvelope)) {
        return error("Invalid offchainEnvelope", 400);
      }

      const limited = await rateLimited(req, {
        endpoint: "register",
        appId,
        identifier: body.email ?? body.publicKey,
      });
      if (limited) return limited;

      if (await getUserByPublicKey(store, appId, body.publicKey)) {
        return error("Account already exists", 409);
      }
      // Email collision check. The client mints a fresh random publicKey on
      // every register attempt (Keypair.generate()), so without this check the
      // publicKey-only collision check above would never fire for email/
      // biometric signups, and every "Sign in or create account" attempt
      // would silently overwrite the email→publicKey index. Returning 409 here
      // lets the client's "auto" mode fall back to loginWithEmail and recover
      // the original publicKey (the appKey is deterministic, so decryption of
      // the original wallets still succeeds).
      // Per-APP email collision check: 409 only if THIS email already has an entry for
      // THIS appId. The same email on a different app is fine — registration adds a new
      // {appId -> publicKey} field to the shared email index instead of colliding (v0.4.0).
      if (body.email) {
        const existing = await resolvePublicKeyByEmail(store, appId, body.email);
        if (existing) return error("Account already exists", 409);
      }

      // Web3 registrations must prove wallet ownership. Verify the signature BEFORE
      // consuming the single-use challenge, so a forged signature can't burn a
      // victim's pending challenge (matches login/loginWallet/connectWallet — WI-5).
      if (body.authMethod === "wallet") {
        if (!body.signature || !body.challenge) return error("signature and challenge required");
        if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin)) {
          return error("Signature verification failed", 401);
        }
        const ok = await consumeChallenge(store, appId, body.publicKey, body.challenge);
        if (!ok) return error("Invalid or expired challenge", 401);
      } else if (!body.authPublicKey) {
        return error("authPublicKey required for email/biometric registration");
      }

      // Every collision check has passed, so this request WILL create a record. Charge the
      // deployment-wide ceiling here — not at the top — so a returning user's 409 (the
      // client's "auto" mode registers first, then falls back to login) costs nothing.
      const capped = await accountCreationLimited();
      if (capped) return capped;

      const user: UserData = {
        appId,
        publicKey: body.publicKey,
        email: body.email,
        authPublicKey: body.authPublicKey,
        authMethod: body.authMethod ?? "email",
        wallets,
        // PBKDF2 iteration count the client derived the app key with (email users);
        // pinned so the same count is used on every future login/unlock. Undefined for
        // wallet/biometric (they don't use PBKDF2).
        pbkdf2Iterations: body.pbkdf2Iterations,
        // Hardware wallets pin the off-chain layout they signed under; absent otherwise.
        offchainEnvelope: body.offchainEnvelope,
        // Real timestamp is stamped by the runtime; tests can inject via storage.
        createdAt: Date.now(),
      };
      await persistUser(store, user);
      const token = await issueSession(store, user, config, issueFingerprint(req));
      return json(asResult(user, token), 201);
    },

    async login(req) {
      const body = await readJson<{
        appId?: string;
        email?: string;
        signature?: string;
        challenge?: string;
      }>(req);
      if (!body?.email || !body.signature || !body.challenge) {
        return error("email, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      // Validate the email BEFORE it reaches a storage key (v0.5.0). /register has always
      // done this; /login did not, so an unauthenticated caller could submit a 1 MB
      // `email` and have it become a key. Inert on Redis (keys are unbounded and the
      // lookup just misses) — but on a SQL backend that is an unauthenticated 500
      // (Postgres) or a silent key truncation (non-strict MySQL). It also invalidates the
      // ≤320-byte bound every backend's column sizing is derived from. Rejects only input
      // that was already outside the documented format.
      const emailErr = validateEmail(body.email);
      if (emailErr) return error(emailErr);

      // Verify the signature FIRST, then rate-limit only on FAILURE. Two reasons:
      //  1. A valid login is never throttled, so an attacker spamming failed logins
      //     for a victim's email cannot lock the victim out of their own correct
      //     login — only failed attempts feed the counter (AUTHSESSION-3).
      //  2. We check the (storage-free) ed25519 signature before consuming the
      //     single-use challenge, so a junk signature can't burn a victim's pending
      //     challenge — only the real key-holder's request reaches consumeChallenge.
      // The server holds no passkey-derived secret; auth is proof-of-control of the key.
      const publicKey = await resolvePublicKeyByEmail(store, appId, body.email);
      const user = publicKey ? await getUserByPublicKey(store, appId, publicKey) : null;
      const sigValid =
        !!user?.authPublicKey && verifyAuthSignature(user.authPublicKey, body.signature, body.challenge);
      const consumed =
        sigValid && publicKey ? await consumeChallenge(store, appId, publicKey, body.challenge) : false;
      if (user && sigValid && consumed) {
        const token = await issueSession(store, user, config, issueFingerprint(req));
        return json(asResult(user, token));
      }
      const limited = await rateLimited(req, { endpoint: "login", appId, identifier: body.email });
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    async loginWallet(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        signature?: string;
        challenge?: string;
      }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);

      // Verify-first, penalize-on-failure (see login). A junk signature never
      // reaches consumeChallenge, so it can't burn a pending challenge, and a valid
      // wallet login is never throttled by an attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin);
      const consumed = sigValid
        ? await consumeChallenge(store, appId, body.publicKey, body.challenge)
        : false;
      if (sigValid && consumed) {
        const user = await getUserByPublicKey(store, appId, body.publicKey);
        // A valid signature proves key ownership; a missing account is not an attack,
        // so don't feed the failure counter — just report it.
        // 422, not 404. The request was well-formed AND the signature verified — the caller
        // genuinely holds this key — there is simply no account to log in to yet. 404 would
        // say the endpoint is missing; 400 would say the request was malformed, and it was
        // not; 401 would say the credential failed, and it did not. A distinct status lets a
        // client branch straight to registration instead of parsing the message.
        if (!user) return error("Wallet not registered", 422);
        const token = await issueSession(store, user, config, issueFingerprint(req));
        return json(asResult(user, token));
      }
      const limited = await rateLimited(req, {
        endpoint: "login",
        appId,
        identifier: body.publicKey,
      });
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    // Login-or-register for a Web3 wallet in one round trip. New wallets are
    // created with the client-provided encrypted bundle; existing wallets log in
    // (provided bundle ignored — their stored keys were encrypted with the same
    // deterministic key and must not be overwritten).
    async connectWallet(req) {
      const body = await readJson<{
        appId?: string;
        publicKey?: string;
        signature?: string;
        challenge?: string;
        wallets?: EncryptedWallet[];
        offchainEnvelope?: OffchainEnvelope;
      }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const appId = body.appId ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);
      if (body.offchainEnvelope != null && !validEnvelope(body.offchainEnvelope)) {
        return error("Invalid offchainEnvelope", 400);
      }
      let wallets: EncryptedWallet[] = [];
      if (body.wallets !== undefined) {
        const r = readWallets(body.wallets);
        if ("error" in r) return r.error;
        wallets = r.wallets;
      }

      // Verify-first, penalize-on-failure (see login): a junk signature can't burn
      // the challenge, and a returning wallet's valid connect isn't throttled by an
      // attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge, config.origin);
      const consumed = sigValid
        ? await consumeChallenge(store, appId, body.publicKey, body.challenge)
        : false;
      if (!(sigValid && consumed)) {
        const limited = await rateLimited(req, {
          endpoint: "connect",
          appId,
          identifier: body.publicKey,
        });
        if (limited) return limited;
        return error("Invalid credentials", 401);
      }

      let user = await getUserByPublicKey(store, appId, body.publicKey);
      const isNew = !user;
      if (!user) {
        // The other creation path. A valid signature is required to get here, but keypairs
        // are free to generate, so without this it is the same unbounded record creation
        // by a different door.
        const cappedNew = await accountCreationLimited();
        if (cappedNew) return cappedNew;
        user = {
          appId,
          publicKey: body.publicKey,
          authMethod: "wallet",
          wallets,
          offchainEnvelope: body.offchainEnvelope,
          createdAt: Date.now(),
        };
        await persistUser(store, user);
      } else if (!user.wallets?.length && wallets.length) {
        // Self-heal: an existing wallet with no stored keys yet (legacy/empty
        // record) gets backfilled from the client bundle. Safe — nothing to
        // overwrite. Wallets that already have keys are never touched.
        // Slot-scoped, for the same reason as import: never rewrite the whole record.
        for (const w of wallets) await store.putWalletSlot(user.appId, user.publicKey, w);
        user.wallets = wallets;
      }
      const token = await issueSession(store, user, config, issueFingerprint(req));
      return json(asResult(user, token), isNew ? 201 : 200);
    },

    // Revoke the current session. Always returns 200 { ok: true } and never leaks
    // whether the presented token was valid.
    async logout(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (appId && user && token) await revokeSession(store, appId, token);
      return json({ ok: true });
    },

    async userData(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (!user) return error("Unauthorized", 401);
      return json({ user: publicUser(user) });
    },

    async searchWallet(req) {
      const url = new URL(req.url);
      const publicKey = url.searchParams.get("publicKey");
      if (!publicKey) return error("publicKey required");
      const appId = url.searchParams.get("appId") ?? config.appId;
      const appErr = validateAppId(appId, config);
      if (appErr) return error(appErr);
      const pkErr = validatePublicKey(publicKey);
      if (pkErr) return error(pkErr);
      // Per-target rate limiting (see challenge): keyed by the queried (app, publicKey)
      // so one abuser can't exhaust a shared bucket and block all existence lookups.
      const limited = await rateLimited(req, { endpoint: "search", appId, identifier: publicKey });
      if (limited) return limited;
      const user = await getUserByPublicKey(store, appId, publicKey);
      // A SEARCH that matched nothing is a successful search, not a missing resource, so
      // it answers 200 with `exists: false` rather than 404. The query was well-formed and
      // ran; "no result" is the result. 404 would claim the endpoint itself is absent.
      //
      // NOTE: this does not close the enumeration oracle (audit.md L-3) — the body still
      // distinguishes a registered wallet from an unregistered one, which is the endpoint's
      // entire purpose. It only stops that answer being carried by a status code that means
      // something else.
      return json({ exists: !!user });
    },

    async importWallet(req) {
      const appId = headerAppId(req);
      const token = req.headers.get(AUTH_TOKEN_HEADER);
      const publicKey = req.headers.get(PUBLIC_KEY_HEADER);
      const user = appId ? await verifySession(store, appId, token, publicKey, reqFingerprint(req)) : null;
      if (!user) return error("Unauthorized", 401);

      const body = await readJson<{ wallets?: EncryptedWallet[] }>(req);
      if (!body?.wallets?.length) return error("wallets required");
      const parsed = readWallets(body.wallets);
      if ("error" in parsed) return parsed.error;

      // REPLACE the (chain, role) slot — never append. Appending was a fund-misdirection
      // bug, not just bloat: `useActiveWallet` resolves a wallet with `.find()`, which
      // returns the FIRST match, while an appended import lands LAST. Importing an EVM
      // funds wallet therefore left the OLD address active, so the app kept displaying it
      // as the deposit address and kept signing with it — the user's replacement silently
      // did nothing. Replacing in place makes the record's four slots authoritative.
      // One slot-scoped write per wallet — NOT a whole-record rewrite. Writing the record
      // back wholesale is what destroyed keys: a concurrent login (which also rewrote it)
      // or a second import would resolve last-write-wins and drop the other's ciphertext,
      // silently, with both requests returning 200.
      for (const incoming of parsed.wallets) {
        await store.putWalletSlot(user.appId, user.publicKey, incoming);
      }
      const updated = (await getUserByPublicKey(store, user.appId, user.publicKey)) ?? user;
      return json({ user: publicUser(updated) });
    },
  };
}
