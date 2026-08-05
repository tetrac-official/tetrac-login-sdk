// Issue and consume single-use, TTL-bound wallet-login challenges.
import type { AuthStore } from "../storage/store.js";
import type { AuthConfig } from "../core/config.js";
import { generateChallenge } from "../core/crypto.js";

/** Exactly what generateChallenge() produces: 256 bits as 64 hex chars. */
const CHALLENGE_RE = /^[0-9a-f]{64}$/i;

/** Create a challenge for an (app, public key) pair and store it with the configured TTL. */
export async function issueChallenge(
  store: AuthStore,
  appId: string,
  publicKey: string,
  config: AuthConfig,
): Promise<string> {
  const challenge = generateChallenge();
  await store.putChallenge(appId, publicKey, challenge, config.challengeTtlSeconds);
  return challenge;
}

/**
 * Atomically fetch-and-delete a presented challenge for a public key.
 * Returns false if missing, expired, or mismatched.
 *
 * `takeChallenge` is REQUIRED to be atomic — it is the sole mechanism closing the
 * get-then-delete replay race: two concurrent consumes must not both read the same
 * challenge before either deletes it, so only one sees the value. The comparison is
 * constant-time and happens HERE, never in the backend.
 */
export async function consumeChallenge(
  store: AuthStore,
  appId: string,
  publicKey: string,
  presented: string,
): Promise<boolean> {
  // The presented value becomes part of a storage key, so it is validated to the exact
  // shape generateChallenge() mints — 64 hex chars — BEFORE it reaches the backend. That
  // bounds the key and makes the ':' namespace separator unrepresentable.
  if (!CHALLENGE_RE.test(presented)) return false;
  // Consume THIS value. Matching happens on an exact key / primary key rather than by
  // comparing a fetched string, so there is no fetched secret to compare in variable time.
  // A challenge is not a secret the attacker guesses anyway: it is server-issued, public
  // to the holder, and useless without a signature over it.
  return store.takeChallenge(appId, publicKey, presented);
}
