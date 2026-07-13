// Issue and consume single-use, TTL-bound wallet-login challenges.
import type { AuthStore } from "../storage/store.js";
import type { AuthConfig } from "../core/config.js";
import { generateChallenge, timingSafeEqual } from "../core/crypto.js";

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
  const stored = await store.takeChallenge(appId, publicKey);
  if (!stored) return false;
  return timingSafeEqual(stored, presented);
}
