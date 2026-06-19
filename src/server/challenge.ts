// Issue and consume single-use, TTL-bound wallet-login challenges.
import type { StorageAdapter } from "../storage/adapter.js";
import type { AuthConfig } from "../core/config.js";
import { generateChallenge, timingSafeEqual } from "../core/crypto.js";
import { appScoped } from "./keys.js";

/** Create a challenge for an (app, public key) pair and store it with the configured TTL. */
export async function issueChallenge(
  storage: StorageAdapter,
  appId: string,
  publicKey: string,
  config: AuthConfig,
): Promise<string> {
  const challenge = generateChallenge();
  await storage.set(appScoped(config.keyPrefixes.challenge, appId, publicKey), challenge, {
    exSeconds: config.challengeTtlSeconds,
  });
  return challenge;
}

/**
 * Atomically fetch-and-delete a presented challenge for a public key.
 * Returns false if missing, expired, or mismatched. The single getdel closes the
 * get-then-del replay race: two concurrent consumes can't both read the same
 * challenge before either deletes it — only one sees the value.
 */
export async function consumeChallenge(
  storage: StorageAdapter,
  appId: string,
  publicKey: string,
  presented: string,
  config: AuthConfig,
): Promise<boolean> {
  const key = appScoped(config.keyPrefixes.challenge, appId, publicKey);
  const stored = await storage.getdel(key);
  if (!stored) return false;
  return timingSafeEqual(stored, presented);
}
