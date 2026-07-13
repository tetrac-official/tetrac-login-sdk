// Rate limiting, delegated to the storage backend as a single atomic DECISION.
import type { AuthStore, RateLimitBucket, RateLimitResult } from "../storage/store.js";
import type { RateLimitConfig } from "../core/config.js";

export type { RateLimitBucket, RateLimitResult };

/**
 * Report whether `bucket` is still under its limit, counting this hit.
 *
 * This is deliberately a one-liner. Before v0.5.0 it was a two-step dance over KV
 * primitives — `incr`, then infer "first hit of a new window" from `count === 1` and
 * only THEN stamp the TTL — and that inference is the origin of the worst bug in the
 * storage layer: a backend whose `incr` returns 16 (not 1) for a stale, expired counter
 * never stamps the new window's TTL, so the identifier — an IP, an email, a public key —
 * stays rate-limited FOREVER.
 *
 * Handing the backend the whole decision makes that class of bug unrepresentable, and it
 * lets backends that need to shard the counter (any OCC engine — a hot counter is many
 * writes to one row) do so invisibly. The window semantics are now the store's contract.
 *
 * NOTE (fail closed): there is no try/catch here, on purpose. If the store throws, the
 * exception propagates and the request 500s. A rate limiter that cannot count must not
 * grant permission.
 */
export async function checkRateLimit(
  store: AuthStore,
  bucket: RateLimitBucket,
  config: RateLimitConfig,
): Promise<RateLimitResult> {
  return store.hitRateLimit(bucket, config.windowSeconds, config.maxAttempts);
}
