// Opaque-token sessions (no JWT): a random token is stored alongside the user
// and validated on each request. Matches next-ttc's model.
import type { StorageAdapter } from "../storage/adapter.js";
import type { AuthConfig } from "../core/config.js";
import type { UserData } from "../core/types.js";
import { generateSessionToken } from "../core/crypto.js";

/** Persist UserData under pubKey:{publicKey} and (for email users) email->pubKey. */
export async function persistUser(
  storage: StorageAdapter,
  user: UserData,
  config: AuthConfig,
): Promise<void> {
  await storage.set(`${config.keyPrefixes.pubKey}${user.publicKey}`, JSON.stringify(user));
  if (user.email) {
    await storage.set(`${config.keyPrefixes.email}${user.email.toLowerCase().trim()}`, user.publicKey);
  }
}

export async function getUserByPublicKey(
  storage: StorageAdapter,
  publicKey: string,
  config: AuthConfig,
): Promise<UserData | null> {
  const raw = await storage.get(`${config.keyPrefixes.pubKey}${publicKey}`);
  return raw ? (JSON.parse(raw) as UserData) : null;
}

export async function resolvePublicKeyByEmail(
  storage: StorageAdapter,
  email: string,
  config: AuthConfig,
): Promise<string | null> {
  return storage.get(`${config.keyPrefixes.email}${email.toLowerCase().trim()}`);
}

/** Issue a new session token and bind it to the user record. */
export async function issueSession(
  storage: StorageAdapter,
  user: UserData,
  config: AuthConfig,
): Promise<string> {
  const token = generateSessionToken();
  // token -> publicKey lookup so verifySession is O(1).
  await storage.set(sessionKey(token, config), user.publicKey);
  user.authToken = token;
  await persistUser(storage, user, config);
  return token;
}

/** Validate the token + public-key pair from request headers. Returns the user or null. */
export async function verifySession(
  storage: StorageAdapter,
  token: string | null | undefined,
  publicKey: string | null | undefined,
  config: AuthConfig,
): Promise<UserData | null> {
  if (!token || !publicKey) return null;
  const owner = await storage.get(sessionKey(token, config));
  if (!owner || owner !== publicKey) return null;
  return getUserByPublicKey(storage, publicKey, config);
}

export async function revokeSession(
  storage: StorageAdapter,
  token: string,
  config: AuthConfig,
): Promise<void> {
  await storage.del(sessionKey(token, config));
}

function sessionKey(token: string, config: AuthConfig): string {
  return `${config.keyPrefixes.pubKey}session:${token}`;
}
