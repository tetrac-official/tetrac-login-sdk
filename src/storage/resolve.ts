// Auto-select a storage adapter from the environment, mirroring next-ttc's db.ts.
// Uses dynamic imports so an unused client is never bundled or required.
import type { StorageAdapter } from "./adapter.js";
import { RedisAdapter } from "./redis.js";
import { VercelKVAdapter, UpstashAdapter } from "./kv.js";

const env = (k: string): string | undefined =>
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[k];

const DEFAULT_REDIS_URL = "redis://localhost:6379";

export type StorageBackend =
  | { kind: "upstash" }
  | { kind: "vercelkv" }
  | { kind: "ioredis"; url: string };

/**
 * Decide which backend the environment selects — PURE (no I/O, no client
 * construction), so the production safety-guard is unit-testable without opening a
 * Redis connection. Order:
 *   1. Upstash REST  (UPSTASH_REDIS_REST_URL + _TOKEN)
 *   2. Vercel KV     (VERCEL set, or KV_REST_API_URL present)
 *   3. ioredis       (REDIS_URL, else redis://localhost:6379 in dev)
 *
 * In production (NODE_ENV==='production') with NO recognized backend configured,
 * this THROWS instead of silently returning the localhost fallback — that almost
 * always means the backend env wasn't wired up, and you'd otherwise get an
 * isolated, ephemeral per-instance store (sessions/challenges that neither persist
 * nor are shared across instances). (SERVERSIDE-10 / WI-10.)
 */
export function selectStorageBackend(): StorageBackend {
  const isProd = env("NODE_ENV") === "production";

  // Partial Upstash config is almost always a deploy mistake — warn loudly so it
  // doesn't silently fall through to a different (or refused) backend.
  if (env("UPSTASH_REDIS_REST_URL") && !env("UPSTASH_REDIS_REST_TOKEN")) {
    // eslint-disable-next-line no-console
    console.warn(
      "[tetrac] UPSTASH_REDIS_REST_URL is set but UPSTASH_REDIS_REST_TOKEN is missing — ignoring the Upstash config.",
    );
  }

  if (env("UPSTASH_REDIS_REST_URL") && env("UPSTASH_REDIS_REST_TOKEN")) return { kind: "upstash" };
  if (env("VERCEL") || env("KV_REST_API_URL")) return { kind: "vercelkv" };

  if (isProd && !env("REDIS_URL")) {
    throw new Error(
      "[tetrac] No storage backend configured in production. Set one of " +
        "UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN, KV_REST_API_URL (or VERCEL), or REDIS_URL. " +
        `Refusing to silently fall back to ${DEFAULT_REDIS_URL} — it would give each instance its own ephemeral store.`,
    );
  }

  return { kind: "ioredis", url: env("REDIS_URL") ?? DEFAULT_REDIS_URL };
}

/** Construct the adapter selected by {@link selectStorageBackend}. */
export async function resolveStorageAdapter(): Promise<StorageAdapter> {
  const backend = selectStorageBackend();

  if (backend.kind === "upstash") {
    const { Redis } = await import("@upstash/redis");
    return new UpstashAdapter(
      new Redis({
        url: env("UPSTASH_REDIS_REST_URL")!,
        token: env("UPSTASH_REDIS_REST_TOKEN")!,
      }) as never,
    );
  }

  if (backend.kind === "vercelkv") {
    const { kv } = await import("@vercel/kv");
    return new VercelKVAdapter(kv as never);
  }

  const { default: Redis } = await import("ioredis");
  return new RedisAdapter(new Redis(backend.url) as never);
}
