// Framework-agnostic auth route handlers built on the Web Request/Response API.
// Next.js App Router consumes these directly via src/next.
import type { StorageAdapter } from "../storage/adapter.js";
import { resolveConfig, type AuthConfig, type DeepPartial } from "../core/config.js";
import type { AuthResult, EncryptedWallet, UserData } from "../core/types.js";
import { json, error, clientIp, readJson } from "./http.js";
import { checkRateLimit } from "./rateLimit.js";
import { issueChallenge, consumeChallenge } from "./challenge.js";
import { verifySolanaSignature } from "./signature.js";
import {
  persistUser,
  getUserByPublicKey,
  resolvePublicKeyByEmail,
  issueSession,
  verifySession,
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
  userData(req: Request): Promise<Response>;
  searchWallet(req: Request): Promise<Response>;
  importWallet(req: Request): Promise<Response>;
}

export function createAuthHandlers(opts: AuthHandlerOptions): AuthHandlers {
  const { storage } = opts;
  const config = resolveConfig(opts.config);

  // Apply dual-key (IP + identifier) rate limiting; returns a 429 Response or null.
  async function rateLimited(req: Request, identifier?: string): Promise<Response | null> {
    const ip = await checkRateLimit(storage, clientIp(req), config.rateLimit, config.keyPrefixes);
    if (!ip.allowed) return error("Rate limit exceeded", 429);
    if (identifier) {
      const id = await checkRateLimit(storage, identifier, config.rateLimit, config.keyPrefixes);
      if (!id.allowed) return error("Rate limit exceeded", 429);
    }
    return null;
  }

  function asResult(user: UserData): AuthResult {
    return { publicKey: user.publicKey, authToken: String(user.authToken), user };
  }

  return {
    config,

    async challenge(req) {
      const limited = await rateLimited(req);
      if (limited) return limited;
      const body = await readJson<{ publicKey?: string }>(req);
      if (!body?.publicKey) return error("publicKey required");
      const challenge = await issueChallenge(storage, body.publicKey, config);
      return json({ challenge });
    },

    async register(req) {
      const body = await readJson<{
        publicKey?: string;
        email?: string;
        passkeyHash?: string;
        authMethod?: UserData["authMethod"];
        wallets?: EncryptedWallet[];
        signature?: string;
        challenge?: string;
      }>(req);
      if (!body?.publicKey) return error("publicKey required");

      const limited = await rateLimited(req, body.email ?? body.publicKey);
      if (limited) return limited;

      if (await getUserByPublicKey(storage, body.publicKey, config)) {
        return error("Account already exists", 409);
      }

      // Web3 registrations must prove wallet ownership.
      if (body.authMethod === "wallet") {
        if (!body.signature || !body.challenge) return error("signature and challenge required");
        const ok = await consumeChallenge(storage, body.publicKey, body.challenge, config);
        if (!ok) return error("Invalid or expired challenge", 401);
        if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge)) {
          return error("Signature verification failed", 401);
        }
      } else if (!body.passkeyHash) {
        return error("passkeyHash required for email/biometric registration");
      }

      const user: UserData = {
        publicKey: body.publicKey,
        email: body.email,
        passkeyHash: body.passkeyHash,
        authMethod: body.authMethod ?? "email",
        wallets: body.wallets ?? [],
        // Real timestamp is stamped by the runtime; tests can inject via storage.
        createdAt: Date.now(),
      };
      await persistUser(storage, user, config);
      await issueSession(storage, user, config);
      return json(asResult(user), 201);
    },

    async login(req) {
      const body = await readJson<{ email?: string; passkeyHash?: string }>(req);
      if (!body?.email || !body.passkeyHash) return error("email and passkeyHash required");

      const limited = await rateLimited(req, body.email);
      if (limited) return limited;

      const publicKey = await resolvePublicKeyByEmail(storage, body.email, config);
      if (!publicKey) return error("Invalid credentials", 401);
      const user = await getUserByPublicKey(storage, publicKey, config);
      if (!user || user.passkeyHash !== body.passkeyHash) {
        return error("Invalid credentials", 401);
      }
      await issueSession(storage, user, config);
      return json(asResult(user));
    },

    async loginWallet(req) {
      const body = await readJson<{ publicKey?: string; signature?: string; challenge?: string }>(req);
      if (!body?.publicKey || !body.signature || !body.challenge) {
        return error("publicKey, signature and challenge required");
      }

      const limited = await rateLimited(req, body.publicKey);
      if (limited) return limited;

      const ok = await consumeChallenge(storage, body.publicKey, body.challenge, config);
      if (!ok) return error("Invalid or expired challenge", 401);
      if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge)) {
        return error("Signature verification failed", 401);
      }
      const user = await getUserByPublicKey(storage, body.publicKey, config);
      if (!user) return error("Wallet not registered", 404);
      await issueSession(storage, user, config);
      return json(asResult(user));
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

      const limited = await rateLimited(req, body.publicKey);
      if (limited) return limited;

      const ok = await consumeChallenge(storage, body.publicKey, body.challenge, config);
      if (!ok) return error("Invalid or expired challenge", 401);
      if (!verifySolanaSignature(body.publicKey, body.signature, body.challenge)) {
        return error("Signature verification failed", 401);
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
      await issueSession(storage, user, config);
      return json(asResult(user), isNew ? 201 : 200);
    },

    async userData(req) {
      const token = req.headers.get(config.sessionHeader);
      const publicKey = req.headers.get(config.publicKeyHeader);
      const user = await verifySession(storage, token, publicKey, config);
      if (!user) return error("Unauthorized", 401);
      return json({ user });
    },

    async searchWallet(req) {
      const publicKey = new URL(req.url).searchParams.get("publicKey");
      if (!publicKey) return error("publicKey required");
      const user = await getUserByPublicKey(storage, publicKey, config);
      return user ? json({ exists: true }) : error("Wallet not found", 404);
    },

    async importWallet(req) {
      const token = req.headers.get(config.sessionHeader);
      const publicKey = req.headers.get(config.publicKeyHeader);
      const user = await verifySession(storage, token, publicKey, config);
      if (!user) return error("Unauthorized", 401);

      const body = await readJson<{ wallets?: EncryptedWallet[] }>(req);
      if (!body?.wallets?.length) return error("wallets required");
      user.wallets = [...user.wallets, ...body.wallets];
      await persistUser(storage, user, config);
      return json({ user });
    },
  };
}
