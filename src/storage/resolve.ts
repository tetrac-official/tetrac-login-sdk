// Auto-select a storage adapter from the environment, mirroring next-ttc's db.ts.
// Uses dynamic imports so an unused client is never bundled or required.
import type { StorageAdapter } from "./adapter.js";
import { RedisAdapter } from "./redis.js";
import { VercelKVAdapter, UpstashAdapter } from "./kv.js";

const env = (k: string): string | undefined =>
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[k];

/**
 * Resolve an adapter:
 *   1. Upstash REST  (UPSTASH_REDIS_REST_URL + _TOKEN)
 *   2. Vercel KV     (VERCEL set, or KV_REST_API_URL present)
 *   3. ioredis       (REDIS_URL, default redis://localhost:6379)
 */
export async function resolveStorageAdapter(): Promise<StorageAdapter> {
  if (env("UPSTASH_REDIS_REST_URL") && env("UPSTASH_REDIS_REST_TOKEN")) {
    const { Redis } = await import("@upstash/redis");
    return new UpstashAdapter(
      new Redis({
        url: env("UPSTASH_REDIS_REST_URL")!,
        token: env("UPSTASH_REDIS_REST_TOKEN")!,
      }) as never,
    );
  }

  if (env("VERCEL") || env("KV_REST_API_URL")) {
    const { kv } = await import("@vercel/kv");
    return new VercelKVAdapter(kv as never);
  }

  const { default: Redis } = await import("ioredis");
  const client = new Redis(env("REDIS_URL") ?? "redis://localhost:6379");
  return new RedisAdapter(client as never);
}
