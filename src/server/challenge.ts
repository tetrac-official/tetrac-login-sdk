// Issue and consume single-use, TTL-bound wallet-login challenges.
import type { StorageAdapter } from "../storage/adapter.js";
import type { AuthConfig } from "../core/config.js";
import { generateChallenge } from "../core/crypto.js";

/** Create a challenge for a public key and store it with the configured TTL. */
export async function issueChallenge(
  storage: StorageAdapter,
  publicKey: string,
  config: AuthConfig,
): Promise<string> {
  const challenge = generateChallenge();
  await storage.set(`${config.keyPrefixes.challenge}${publicKey}`, challenge, {
    exSeconds: config.challengeTtlSeconds,
  });
  return challenge;
}

/**
 * Verify a presented challenge for a public key, then delete it (single-use).
 * Returns false if missing, expired, or mismatched.
 */
export async function consumeChallenge(
  storage: StorageAdapter,
  publicKey: string,
  presented: string,
  config: AuthConfig,
): Promise<boolean> {
  const key = `${config.keyPrefixes.challenge}${publicKey}`;
  const stored = await storage.get(key);
  if (!stored || stored !== presented) return false;
  await storage.del(key); // single-use: prevents replay
  return true;
}
