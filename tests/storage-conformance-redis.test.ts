// The conformance suite against a REAL Redis. (PRD/v0.5.0-PRD.md §3.4 — the last open item.)
//
// WHY THIS FILE EXISTS, and why a mock would not do:
//
// `MemoryAdapter` is the SDK's **normative reference implementation** — the thing every future
// backend (Postgres, Mongo, DynamoDB, Convex) is written to match, and the thing the conformance
// suite is calibrated against. But "MemoryAdapter matches Redis" has, until now, been an
// ASSERTION IN A CODE COMMENT that was never executed.
//
// That matters because the invariants in question are properties of the ENGINE, not of our code:
//   - does INCR on an EXPIRED key really return 1 (and drop the stale TTL)?   [permanent lockout]
//   - does INCR on a LIVE key really preserve its TTL?                        [window drift]
//   - is GETDEL really atomic under concurrency?                              [challenge replay]
//   - is an expired key really invisible on every read path?                  [expired sessions]
// A mock only asserts that we mocked Redis the way we IMAGINED it. If our mental model is wrong,
// every adapter built on the reference implementation inherits the same wrong model.
//
// So: run the real suite, against a real engine, over the real ioredis client. If the reference
// implementation is wrong, this is the cheap release to find out — before three SQL adapters are
// built on top of it.
//
// SKIPPED unless REDIS_URL is set, so `npm test` stays green on a laptop with no Docker:
//   docker run --rm -p 6379:6379 redis:7-alpine
//   REDIS_URL=redis://localhost:6379 npx jest tests/storage-conformance-redis.test.ts
// CI sets it via a `redis:7-alpine` service container (.github/workflows/ci.yml).
import Redis from "ioredis";
import { authStoreConformanceCases } from "../src/storage/conformance";
import { KvAuthStore } from "../src/storage/store";
import { RedisAdapter } from "../src/storage/redis";
import type { KeyPrefixes } from "../src/core/config";

const REDIS_URL = process.env.REDIS_URL;

// Every case gets its own keyspace. The suite calls makeStore() once per case, and they all share
// one Redis DB — without this, a key written by one case would be visible to the next. (Namespacing
// rather than FLUSHDB on purpose: this must be safe to point at a Redis that isn't ours.)
let ns = 0;
function freshPrefixes(): KeyPrefixes {
  const p = `conf${++ns}:${Date.now()}:`;
  return {
    challenge: `${p}challenge:`,
    pubKey: `${p}pubKey:`,
    session: `${p}session:`,
    email: `${p}email:`,
    rateLimit: `${p}ratelimit:`,
  };
}

const clients: Redis[] = [];

// No `advance` clock: against a real engine the suite REALLY SLEEPS, which is the point — we are
// testing Redis's own expiry, not our simulation of it. TTLs in the expiry cases are 1s.
//
// supportsSweep is FALSE, and that is itself a conformance claim: Redis expiry is native and exact,
// so RedisAdapter correctly OMITS sweepExpired — and KvAuthStore must not invent one on its behalf.
const cases = REDIS_URL
  ? authStoreConformanceCases(
      () => {
        // A fresh client per case: the suite closes the store in a `finally`, and KvAuthStore over
        // RedisAdapter genuinely exposes close() (ioredis holds a socket). So this also exercises
        // the v0.5.0 close() path ~24 times, against a real connection.
        const client = new Redis(REDIS_URL);
        clients.push(client);
        return new KvAuthStore(new RedisAdapter(client as never), freshPrefixes());
      },
      { supportsSweep: false },
    )
  : [];

const describeRedis = REDIS_URL ? describe : describe.skip;

describeRedis("AuthStore conformance — KvAuthStore over a REAL Redis", () => {
  afterAll(async () => {
    // Belt and braces: the suite already closes each store, but a case that throws before its
    // `finally` could leave a socket open and hang Jest.
    await Promise.all(clients.map((c) => c.quit().catch(() => undefined)));
  });

  it("exposes the full case list", () => {
    expect(cases.length).toBeGreaterThanOrEqual(18);
  });

  // Real sleeps for the expiry/window cases (1s TTLs + margin), so give them room.
  for (const c of cases) {
    it(c.name, () => c.run(), 30_000);
  }
});

// A green-by-vacuity run is the failure mode to fear here: if REDIS_URL is unset in CI, every case
// silently disappears and the suite "passes" while testing nothing. Fail loudly instead.
(process.env.CI ? describe : describe.skip)("real-Redis conformance is WIRED in CI", () => {
  it("REDIS_URL must be set in CI — a skipped suite is not a passing suite", () => {
    expect(REDIS_URL).toBeTruthy();
  });
});
