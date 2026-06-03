// Sliding-window-ish counter rate limiting backed by the storage adapter.
import type { StorageAdapter } from "../storage/adapter.js";
import type { RateLimitConfig, KeyPrefixes } from "../core/config.js";

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

/**
 * Increment the counter for `identifier` (an IP, email, or pubKey) and report
 * whether it is still under the limit. The first hit in a window sets the TTL.
 */
export async function checkRateLimit(
  storage: StorageAdapter,
  identifier: string,
  config: RateLimitConfig,
  prefixes: KeyPrefixes,
): Promise<RateLimitResult> {
  const key = `${prefixes.rateLimit}${identifier}`;
  const count = await storage.incr(key);
  if (count === 1) {
    await storage.expire(key, config.windowSeconds);
  }
  return {
    allowed: count <= config.maxAttempts,
    remaining: Math.max(0, config.maxAttempts - count),
  };
}
