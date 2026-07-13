// The DOMAIN port (v0.5.0) — implement this to back the SDK with a real database.
export {
  KvAuthStore,
  normalizeEmail,
  type AuthStore,
  type SessionValue,
  type RateLimitBucket,
  type RateLimitResult,
} from "./store.js";

// The KV port — implement this only for a Redis-style store with native atomic INCR,
// TTL, and GETDEL. KvAuthStore adapts any of these to an AuthStore.
export type { StorageAdapter, SetOptions } from "./adapter.js";
export { RedisAdapter, type RedisLike } from "./redis.js";
export { VercelKVAdapter, UpstashAdapter, type KvLike } from "./kv.js";
export { MemoryAdapter } from "./memory.js";
export { resolveStorageAdapter } from "./resolve.js";

// NOTE: the conformance suite is deliberately NOT re-exported here. It ships on its own
// subpath (@tetrac/login-sdk/storage/conformance) so it can never be pulled into a
// production server bundle by an `import { ... } from "@tetrac/login-sdk/storage"`.
