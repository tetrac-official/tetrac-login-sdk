// Framework-agnostic auth route handlers built on the Web Request/Response API.
// Next.js App Router consumes these directly via src/next.
import type { StorageAdapter } from "../storage/adapter.js";
import { resolveConfig, type AuthConfig, type DeepPartial } from "../core/config.js";
import type { AuthResult, EncryptedWallet, UserData } from "../core/types.js";
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

export interface AuthHandlerOptions {
  storage: StorageAdapter;
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

function validateEmail(email: string): string | null {
  if (email.length > 320 || !EMAIL_RE.test(email)) return "Invalid email format";
  return null;
}

function validatePublicKey(key: string): string | null {
  // Loose by design: publicKey may be a Solana base58 key, an EVM 0x address, or a
  // biometric identity id — so we only enforce no surrounding whitespace + a length bound.
  if (!key || key.trim() !== key || key.length > 128) return "Invalid publicKey format";
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
function validIterations(n: unknown): boolean {
  return typeof n === "number" && Number.isInteger(n) && n >= PBKDF2_MIN && n <= PBKDF2_MAX;
}

export function createAuthHandlers(opts: AuthHandlerOptions): AuthHandlers {
  const { storage } = opts;
  const config = resolveConfig(opts.config);

  // Apply rate limiting; returns a 429 Response or null. We only gate on the
  // client IP when we actually have a trustworthy one (trustProxyHeaders behind a
  // real proxy); otherwise clientIp() is the constant "unknown" and gating on it
  // would be a GLOBAL lockout vector — one abuser would lock out everyone — so we
  // skip it and rely on the per-target `identifier` bucket below (H5). Every
  // rate-limited endpoint passes a per-target identifier, so nothing is left
  // unprotected when the IP leg is skipped. Callers pass an ENDPOINT-SCOPED
  // identifier (e.g. "challenge:<id>", "login:<id>") so one endpoint's limit can
  // never bleed into and lock a victim out of a DIFFERENT endpoint they need —
  // e.g. failed logins must not exhaust the bucket the victim's /challenge uses.
  async function rateLimited(req: Request, identifier?: string): Promise<Response | null> {
    if (config.trustProxyHeaders) {
      const ip = await checkRateLimit(
        storage,
        clientIp(req, true, config.trustedProxyHops),
        config.rateLimit,
        config.keyPrefixes,
      );
      if (!ip.allowed) return error("Rate limit exceeded", 429);
    }
    if (identifier) {
      const id = await checkRateLimit(storage, identifier, config.rateLimit, config.keyPrefixes);
      if (!id.allowed) return error("Rate limit exceeded", 429);
    }
    return null;
  }

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

  // Client-safe copy of a user record: never echo the session token back to the
  // browser (it travels only in AuthResult.authToken). authPublicKey is public key
  // material, so it is safe to include.
  function publicUser(user: UserData): UserData {
    const { authToken: _authToken, ...safe } = user;
    return safe as UserData;
  }

  function asResult(user: UserData): AuthResult {
    return { publicKey: user.publicKey, authToken: String(user.authToken), user: publicUser(user) };
  }

  // Validate a client-supplied wallets[] payload. Returns an error Response (400)
  // or null when the array is acceptable. Bounds the count and each entry's shape.
  function validateWallets(wallets: unknown): Response | null {
    if (!Array.isArray(wallets)) return error("wallets must be an array");
    if (wallets.length > 16) return error("too many wallets");
    for (const w of wallets) {
      if (!w || typeof w !== "object") return error("invalid wallet entry");
      const e = w as Record<string, unknown>;
      if (typeof e.publicKey !== "string" || typeof e.encryptedSecret !== "string") {
        return error("invalid wallet entry");
      }
      if (e.publicKey.length > 128) return error("wallet publicKey too long");
      if (typeof e.role !== "string" || !e.role) return error("invalid wallet entry");
      if (e.chain !== "solana" && e.chain !== "evm") return error("invalid wallet entry");
      if (e.encryptedSecret.length > 8192) return error("encryptedSecret too large");
    }
    return null;
  }

  return {
    config,

    async challenge(req) {
      const body = await readJson<{ publicKey?: string; email?: string }>(req);
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
        const limited = await rateLimited(req, `challenge:${identifier}`);
        if (limited) return limited;
      }
      // Wallet flow passes publicKey; email/biometric flow passes the account email
      // (or internal biometric id), which we resolve to the identity publicKey.
      let publicKey = body?.publicKey ?? null;
      if (!publicKey && body?.email) {
        publicKey = await resolvePublicKeyByEmail(storage, body.email, config);
      }
      if (!publicKey) return error("publicKey or email required");
      const challenge = await issueChallenge(storage, publicKey, config);
      // Email accounts also need their pinned PBKDF2 iteration count to re-derive the
      // appKey (and thus the auth keypair) before signing — public, not secret.
      const user = body?.email ? await getUserByPublicKey(storage, publicKey, config) : null;
      return json({ challenge, pbkdf2Iterations: user?.pbkdf2Iterations });
    },

    async register(req) {
      const body = await readJson<{
        publicKey?: string;
        email?: string;
        authPublicKey?: string;
        authMethod?: UserData["authMethod"];
        wallets?: EncryptedWallet[];
        signature?: string;
        challenge?: string;
        pbkdf2Iterations?: number;
      }>(req);
      if (!body?.publicKey) return error("publicKey required");
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
      if (body.wallets !== undefined) {
        const invalid = validateWallets(body.wallets);
        if (invalid) return invalid;
      }
      // Reject a client-supplied PBKDF2 count outside the allowed band (audit F3).
      // Absent is fine — legacy/wallet accounts don't pin one.
      if (body.pbkdf2Iterations != null && !validIterations(body.pbkdf2Iterations)) {
        return error("Invalid pbkdf2Iterations", 400);
      }

      const limited = await rateLimited(req, `register:${body.email ?? body.publicKey}`);
      if (limited) return limited;

      if (await getUserByPublicKey(storage, body.publicKey, config)) {
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
      if (body.email) {
        const existing = await resolvePublicKeyByEmail(storage, body.email, config);
        if (existing) return error("Account already exists", 409);
      }

      // Web3 registrations must prove wallet ownership. Verify the signature BEFORE
      // consuming the single-use challenge, so a forged signature can't burn a
      // victim's pending challenge (matches login/loginWallet/connectWallet — WI-5).
      if (body.authMethod === "wallet") {
        if (!body.signature || !body.challenge) return error("signature and challenge required");
        if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge)) {
          return error("Signature verification failed", 401);
        }
        const ok = await consumeChallenge(storage, body.publicKey, body.challenge, config);
        if (!ok) return error("Invalid or expired challenge", 401);
      } else if (!body.authPublicKey) {
        return error("authPublicKey required for email/biometric registration");
      }

      const user: UserData = {
        publicKey: body.publicKey,
        email: body.email,
        authPublicKey: body.authPublicKey,
        authMethod: body.authMethod ?? "email",
        wallets: body.wallets ?? [],
        // PBKDF2 iteration count the client derived the app key with (email users);
        // pinned so the same count is used on every future login/unlock. Undefined for
        // wallet/biometric (they don't use PBKDF2).
        pbkdf2Iterations: body.pbkdf2Iterations,
        // Real timestamp is stamped by the runtime; tests can inject via storage.
        createdAt: Date.now(),
      };
      await persistUser(storage, user, config);
      await issueSession(storage, user, config, issueFingerprint(req));
      return json(asResult(user), 201);
    },

    async login(req) {
      const body = await readJson<{ email?: string; signature?: string; challenge?: string }>(req);
      if (!body?.email || !body.signature || !body.challenge) {
        return error("email, signature and challenge required");
      }

      // Verify the signature FIRST, then rate-limit only on FAILURE. Two reasons:
      //  1. A valid login is never throttled, so an attacker spamming failed logins
      //     for a victim's email cannot lock the victim out of their own correct
      //     login — only failed attempts feed the counter (AUTHSESSION-3).
      //  2. We check the (storage-free) ed25519 signature before consuming the
      //     single-use challenge, so a junk signature can't burn a victim's pending
      //     challenge — only the real key-holder's request reaches consumeChallenge.
      // The server holds no passkey-derived secret; auth is proof-of-control of the key.
      const publicKey = await resolvePublicKeyByEmail(storage, body.email, config);
      const user = publicKey ? await getUserByPublicKey(storage, publicKey, config) : null;
      const sigValid =
        !!user?.authPublicKey && verifyAuthSignature(user.authPublicKey, body.signature, body.challenge);
      const consumed =
        sigValid && publicKey ? await consumeChallenge(storage, publicKey, body.challenge, config) : false;
      if (user && sigValid && consumed) {
        await issueSession(storage, user, config, issueFingerprint(req));
        return json(asResult(user));
      }
      const limited = await rateLimited(req, `login:${body.email}`);
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    async loginWallet(req) {
      const body = await readJson<{ publicKey?: string; signature?: string; challenge?: string }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);

      // Verify-first, penalize-on-failure (see login). A junk signature never
      // reaches consumeChallenge, so it can't burn a pending challenge, and a valid
      // wallet login is never throttled by an attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge);
      const consumed = sigValid
        ? await consumeChallenge(storage, body.publicKey, body.challenge, config)
        : false;
      if (sigValid && consumed) {
        const user = await getUserByPublicKey(storage, body.publicKey, config);
        // A valid signature proves key ownership; a missing account is not an attack,
        // so don't feed the failure counter — just report it.
        if (!user) return error("Wallet not registered", 404);
        await issueSession(storage, user, config, issueFingerprint(req));
        return json(asResult(user));
      }
      const limited = await rateLimited(req, `login:${body.publicKey}`);
      if (limited) return limited;
      return error("Invalid credentials", 401);
    },

    // Login-or-register for a Web3 wallet in one round trip. New wallets are
    // created with the client-provided encrypted bundle; existing wallets log in
    // (provided bundle ignored — their stored keys were encrypted with the same
    // deterministic key and must not be overwritten).
    async connectWallet(req) {
      const body = await readJson<{
        publicKey?: string;
        signature?: string;
        challenge?: string;
        wallets?: EncryptedWallet[];
      }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }
      const pkErr = validatePublicKey(body.publicKey);
      if (pkErr) return error(pkErr);
      if (body.wallets !== undefined) {
        const invalid = validateWallets(body.wallets);
        if (invalid) return invalid;
      }

      // Verify-first, penalize-on-failure (see login): a junk signature can't burn
      // the challenge, and a returning wallet's valid connect isn't throttled by an
      // attacker's failed attempts.
      const sigValid = verifySolanaSignature(body.publicKey, body.signature, body.challenge);
      const consumed = sigValid
        ? await consumeChallenge(storage, body.publicKey, body.challenge, config)
        : false;
      if (!(sigValid && consumed)) {
        const limited = await rateLimited(req, `connect:${body.publicKey}`);
        if (limited) return limited;
        return error("Invalid credentials", 401);
      }

      let user = await getUserByPublicKey(storage, body.publicKey, config);
      const isNew = !user;
      if (!user) {
        user = {
          publicKey: body.publicKey,
          authMethod: "wallet",
          wallets: body.wallets ?? [],
          createdAt: Date.now(),
        };
        await persistUser(storage, user, config);
      } else if (!user.wallets?.length && body.wallets?.length) {
        // Self-heal: an existing wallet with no stored keys yet (legacy/empty
        // record) gets backfilled from the client bundle. Safe — nothing to
        // overwrite. Wallets that already have keys are never touched.
        user.wallets = body.wallets;
        await persistUser(storage, user, config);
      }
      await issueSession(storage, user, config, issueFingerprint(req));
      return json(asResult(user), isNew ? 201 : 200);
    },

    // Revoke the current session. Always returns 200 { ok: true } and never leaks
    // whether the presented token was valid.
    async logout(req) {
      const token = req.headers.get(config.sessionHeader);
      const publicKey = req.headers.get(config.publicKeyHeader);
      const user = await verifySession(storage, token, publicKey, config, reqFingerprint(req));
      if (user && token) await revokeSession(storage, token, config);
      return json({ ok: true });
    },

    async userData(req) {
      const token = req.headers.get(config.sessionHeader);
      const publicKey = req.headers.get(config.publicKeyHeader);
      const user = await verifySession(storage, token, publicKey, config, reqFingerprint(req));
      if (!user) return error("Unauthorized", 401);
      return json({ user: publicUser(user) });
    },

    async searchWallet(req) {
      const publicKey = new URL(req.url).searchParams.get("publicKey");
      if (!publicKey) return error("publicKey required");
      const pkErr = validatePublicKey(publicKey);
      if (pkErr) return error(pkErr);
      // Per-target rate limiting (see challenge): keyed by the queried publicKey so
      // one abuser can't exhaust a shared bucket and block all existence lookups.
      const limited = await rateLimited(req, `search:${publicKey}`);
      if (limited) return limited;
      const user = await getUserByPublicKey(storage, publicKey, config);
      return user ? json({ exists: true }) : error("Wallet not found", 404);
    },

    async importWallet(req) {
      const token = req.headers.get(config.sessionHeader);
      const publicKey = req.headers.get(config.publicKeyHeader);
      const user = await verifySession(storage, token, publicKey, config, reqFingerprint(req));
      if (!user) return error("Unauthorized", 401);

      const body = await readJson<{ wallets?: EncryptedWallet[] }>(req);
      if (!body?.wallets?.length) return error("wallets required");
      const invalid = validateWallets(body.wallets);
      if (invalid) return invalid;
      if (user.wallets.length + body.wallets.length > config.maxWalletsPerUser) {
        return error("wallet limit reached", 400);
      }
      user.wallets = [...user.wallets, ...body.wallets];
      await persistUser(storage, user, config);
      return json({ user: publicUser(user) });
    },
  };
}
