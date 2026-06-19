// Opaque-token sessions (no JWT): a random token is stored alongside the user
// and validated on each request. Matches next-ttc's model.
import type { StorageAdapter } from "../storage/adapter.js";
import type { AuthConfig } from "../core/config.js";
import type { UserData } from "../core/types.js";
import { generateSessionToken, timingSafeEqual } from "../core/crypto.js";
import { appScoped } from "./keys.js";

// The session store value is normally just the owner's publicKey. When UA-binding is
// enabled (config.bindSessionToUserAgent), it becomes "publicKey|fingerprint". Wallet
// public keys (base58 / 0x-hex / hex) never contain "|", so it's an unambiguous split.
function encodeSessionValue(publicKey: string, fingerprint?: string): string {
  return fingerprint ? `${publicKey}|${fingerprint}` : publicKey;
}

function decodeSessionValue(value: string): { publicKey: string; fingerprint?: string } {
  const i = value.indexOf("|");
  return i === -1 ? { publicKey: value } : { publicKey: value.slice(0, i), fingerprint: value.slice(i + 1) };
}

/**
 * Persist UserData under pubKey:{appId}:{publicKey} and (for email users) merge
 * {appId -> publicKey} into the email index hash. The pubKey key is scoped by
 * `user.appId`, so the same wallet/email on a different app is an independent
 * record. The email index key stays bare (`email:{address}`) so one email can
 * answer every app it's registered on (HGETALL → { appId: publicKey }).
 */
export async function persistUser(
  storage: StorageAdapter,
  user: UserData,
  config: AuthConfig,
): Promise<void> {
  await storage.set(appScoped(config.keyPrefixes.pubKey, user.appId, user.publicKey), JSON.stringify(user));
  if (user.email) {
    await storage.hset(emailKey(user.email, config), user.appId, user.publicKey);
  }
}

export async function getUserByPublicKey(
  storage: StorageAdapter,
  appId: string,
  publicKey: string,
  config: AuthConfig,
): Promise<UserData | null> {
  const raw = await storage.get(appScoped(config.keyPrefixes.pubKey, appId, publicKey));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserData;
  } catch {
    return null; // malformed/non-JSON value — fail safe instead of throwing
  }
}

export async function resolvePublicKeyByEmail(
  storage: StorageAdapter,
  appId: string,
  email: string,
  config: AuthConfig,
): Promise<string | null> {
  return storage.hget(emailKey(email, config), appId);
}

function emailKey(email: string, config: AuthConfig): string {
  return `${config.keyPrefixes.email}${email.toLowerCase().trim()}`;
}

/**
 * Issue a new session token and bind it to the user record. When `fingerprint` is
 * supplied (the caller passes a UA hash only if config.bindSessionToUserAgent is on),
 * it is stored with the session and re-checked by verifySession.
 */
export async function issueSession(
  storage: StorageAdapter,
  user: UserData,
  config: AuthConfig,
  fingerprint?: string,
): Promise<string> {
  // Revoke the user's previous token (single active session) before minting a
  // new one, so an old leaked token can't outlive the next login.
  const previous = user.authToken;
  if (typeof previous === "string" && previous) {
    await revokeSession(storage, user.appId, previous, config);
  }
  const token = generateSessionToken();
  // token -> publicKey(|fingerprint) lookup so verifySession is O(1); expires with the configured TTL.
  // The session key is app-scoped, so a token minted by one app is never honored by another.
  await storage.set(sessionKey(user.appId, token, config), encodeSessionValue(user.publicKey, fingerprint), {
    exSeconds: config.sessionTtlSeconds,
  });
  user.authToken = token;
  await persistUser(storage, user, config);
  return token;
}

/**
 * Validate the token + public-key pair from request headers. Returns the user or null.
 * If the session was issued with a UA fingerprint, `presentedFingerprint` must match it
 * (constant-time) — enforced whenever a fingerprint is stored, regardless of the current
 * config flag, so disabling the flag never silently un-binds live sessions.
 */
export async function verifySession(
  storage: StorageAdapter,
  appId: string,
  token: string | null | undefined,
  publicKey: string | null | undefined,
  config: AuthConfig,
  presentedFingerprint?: string,
): Promise<UserData | null> {
  if (!token || !publicKey) return null;
  const value = await storage.get(sessionKey(appId, token, config));
  if (!value) return null;
  const { publicKey: owner, fingerprint: storedFp } = decodeSessionValue(value);
  if (owner !== publicKey) return null;
  if (storedFp && (!presentedFingerprint || !timingSafeEqual(storedFp, presentedFingerprint))) {
    return null;
  }
  return getUserByPublicKey(storage, appId, publicKey, config);
}

export async function revokeSession(
  storage: StorageAdapter,
  appId: string,
  token: string,
  config: AuthConfig,
): Promise<void> {
  await storage.del(sessionKey(appId, token, config));
}

function sessionKey(appId: string, token: string, config: AuthConfig): string {
  return appScoped(config.keyPrefixes.session, appId, token);
}
