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
  // ONE FIELD, not the whole record. Rewriting the entire UserData blob here — which is
  // what persistUser does — made every login race any concurrent wallet write, and the
  // loser's `encryptedSecret` was gone for good: it is the only copy of that private key.
  // A session pointer is a single field, so it gets a single-field write.
  await store.setSessionPointer(user.appId, user.publicKey, tokenHash);
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
  const tokenHash = hashSessionToken(token);
  const session = await store.getSession(appId, tokenHash);
  if (!session) return null;
  if (session.publicKey !== publicKey) return null;
  if (
    session.fingerprint &&
    (!presentedFingerprint || !timingSafeEqual(session.fingerprint, presentedFingerprint))
  ) {
    return null;
  }
  const user = await store.getUser(appId, publicKey);
  if (!user) return null;
  // THE RECORD'S POINTER IS THE AUTHORITY, not the mere existence of a session key.
  //
  // "One active session" was enforced only by issueSession deleting the previous session
  // key, which works when logins are sequential and fails when they overlap: two logins
  // read the same `authTokenHash` off their own snapshots, both delete that same
  // already-gone key, and neither deletes the other's. Both session keys stay live while
  // the record names one of them — so the login that LOST the pointer race kept a fully
  // working token that no later login and no logout could reach, because nothing pointed
  // at it any more. It survived to TTL.
  //
  // Checking the pointer here closes it without a CAS: the race loser is rejected on its
  // next request no matter what is left in the session store. It also fails closed if
  // setSessionPointer ever fails after putSession — an orphaned key is dead, not live.
  //
  // Plain !== is correct: authTokenHash is a SHA-256 digest of a value the caller already
  // presented, not a secret to be guessed, so there is nothing to leak by timing.
  if (user.authTokenHash !== tokenHash) return null;
  return user;
}

/** Revoke a session given its RAW token (as presented in the request header). */
export async function revokeSession(store: AuthStore, appId: string, token: string): Promise<void> {
  await store.deleteSession(appId, hashSessionToken(token));
}
