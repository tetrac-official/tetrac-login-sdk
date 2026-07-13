// Opaque-token sessions (no JWT): a random token is issued to the client, and only its
// SHA-256 DIGEST is ever persisted. Validated on each request.
import type { AuthStore, SessionValue } from "../storage/store.js";
import type { AuthConfig } from "../core/config.js";
import type { UserData } from "../core/types.js";
import { generateSessionToken, timingSafeEqual, hashSessionToken } from "../core/crypto.js";

/**
 * Persist UserData and (for email users) index it under this app's appId. Both writes
 * are the store's business — a native backend does them in one transaction.
 */
export async function persistUser(store: AuthStore, user: UserData): Promise<void> {
  await store.putUser(user);
}

export async function getUserByPublicKey(
  store: AuthStore,
  appId: string,
  publicKey: string,
): Promise<UserData | null> {
  return store.getUser(appId, publicKey);
}

export async function resolvePublicKeyByEmail(
  store: AuthStore,
  appId: string,
  email: string,
): Promise<string | null> {
  return store.getPublicKeyByEmail(appId, email);
}

/**
 * Issue a new session token and bind it to the user record. Returns the RAW token —
 * which is the only place it exists outside the client. Storage sees only its digest.
 *
 * When `fingerprint` is supplied (the caller passes a UA hash only if
 * config.bindSessionToUserAgent is on), it is stored with the session and re-checked by
 * verifySession.
 */
export async function issueSession(
  store: AuthStore,
  user: UserData,
  config: AuthConfig,
  fingerprint?: string,
): Promise<string> {
  // Revoke the user's previous session (single active session) before minting a new one,
  // so an old leaked token can't outlive the next login. We revoke by the stored HASH:
  // we no longer hold the previous raw token, and we don't need it — the digest IS the
  // key.
  const previousHash = user.authTokenHash;
  if (typeof previousHash === "string" && previousHash) {
    await store.deleteSession(user.appId, previousHash);
  }

  const token = generateSessionToken();
  const tokenHash = hashSessionToken(token);
  const value: SessionValue = fingerprint
    ? { publicKey: user.publicKey, fingerprint }
    : { publicKey: user.publicKey };
  // tokenHash -> owner lookup, so verifySession is O(1); expires with the configured TTL.
  // The session is app-scoped, so a token minted by one app is never honored by another.
  await store.putSession(user.appId, tokenHash, value, config.sessionTtlSeconds);

  user.authTokenHash = tokenHash;
  // Scrub the pre-v0.5.0 raw bearer token from records written by an older version. Any
  // user who logs in again is cleaned automatically; a stale one is inert anyway (no
  // session exists under it), so this is hygiene, not a security dependency.
  delete (user as { authToken?: unknown }).authToken;

  await persistUser(store, user);
  return token;
}

/**
 * Validate the token + public-key pair from request headers. Returns the user or null.
 * If the session was issued with a UA fingerprint, `presentedFingerprint` must match it
 * (constant-time) — enforced whenever a fingerprint is stored, regardless of the current
 * config flag, so disabling the flag never silently un-binds live sessions.
 */
export async function verifySession(
  store: AuthStore,
  appId: string,
  token: string | null | undefined,
  publicKey: string | null | undefined,
  presentedFingerprint?: string,
): Promise<UserData | null> {
  if (!token || !publicKey) return null;
  // The store never sees the raw token; it is hashed here, on the way in.
  const session = await store.getSession(appId, hashSessionToken(token));
  if (!session) return null;
  if (session.publicKey !== publicKey) return null;
  if (
    session.fingerprint &&
    (!presentedFingerprint || !timingSafeEqual(session.fingerprint, presentedFingerprint))
  ) {
    return null;
  }
  return store.getUser(appId, publicKey);
}

/** Revoke a session given its RAW token (as presented in the request header). */
export async function revokeSession(store: AuthStore, appId: string, token: string): Promise<void> {
  await store.deleteSession(appId, hashSessionToken(token));
}
