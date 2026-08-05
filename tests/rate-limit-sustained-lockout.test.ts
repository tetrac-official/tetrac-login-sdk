// Targeted denial of service via the rate limiter's own counter.
//
// THE CLAIM UNDER TEST: an unauthenticated attacker can hold a NAMED account locked out
// of login indefinitely, while sending traffic that stays comfortably UNDER the published
// rate limit.
//
// Why that is reachable at all: the auth handlers rate-limit `challenge` and `login` on a
// bucket keyed by a CALLER-SUPPLIED identifier — an email or a public key
// (src/server/routes: `rateLimited(req, { endpoint: "challenge", appId, identifier })`).
// The attacker therefore chooses whose counter to fill. For any deployment where account
// emails are derivable — Tetrac mints `{telegramId}@telegram.tetrac.xyz` — the victim is
// selectable by anyone.
//
// That keying is a deliberate design choice and is fine on its own: a bucket that drains
// on schedule merely throttles, and the victim recovers within one window. The defect is
// that the KV/Redis counter does NOT drain on schedule under sustained traffic, which
// turns throttling into indefinite denial.
//
// These tests drive the REAL KvAuthStore over the REAL MemoryAdapter (the SDK's normative
// reference implementation, which the dockerized Redis conformance run pins to actual
// Redis semantics). The clock is injected so a ten-minute attack runs instantly and
// deterministically — no sleeps, no flakes.
import { KvAuthStore } from "../src/storage/store";
import { MemoryAdapter } from "../src/storage/memory";
import { DEFAULT_CONFIG } from "../src/core/config";
import type { RateLimitBucket } from "../src/storage/store";

// Production-shaped numbers, taken from DEFAULT_CONFIG.rateLimit.
const WINDOW_SECONDS = 60;
const MAX_ATTEMPTS = 10;

/** A store whose clock the test drives directly. */
function makeStore() {
  let now = 1_700_000_000_000;
  const store = new KvAuthStore(new MemoryAdapter(() => now), DEFAULT_CONFIG.keyPrefixes);
  return {
    store,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

// The victim's bucket. `identifier` is attacker-chosen: it is whatever email or public key
// arrives in the request body.
const victimBucket: RateLimitBucket = {
  endpoint: "challenge",
  appId: "tetrac",
  identifier: "424242@telegram.tetrac.xyz",
};

describe("rate limiter — sustained targeted lockout", () => {
  it("published limit is 10 per 60s, so 1 request every 45s is legal traffic", () => {
    // Establishes the premise the attack abuses: the rate below is not merely under the
    // cap, it is under it by ~7x. Nothing about it should ever deny anyone.
    const requestsPerWindow = WINDOW_SECONDS / 45;
    expect(requestsPerWindow).toBeLessThan(MAX_ATTEMPTS);
    expect(DEFAULT_CONFIG.rateLimit.maxAttempts).toBe(MAX_ATTEMPTS);
    expect(DEFAULT_CONFIG.rateLimit.windowSeconds).toBe(WINDOW_SECONDS);
  });

  it("a victim recovers once an attacker STOPS (the limiter throttles, as designed)", async () => {
    // Control case. This is the behaviour that makes keying on a caller-supplied
    // identifier acceptable in the first place, and it holds on the current code — so a
    // failure here would mean the harness itself is wrong.
    const { store, advance } = makeStore();

    for (let i = 0; i < MAX_ATTEMPTS + 5; i++) {
      await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
      advance(1_000);
    }
    expect((await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS)).allowed).toBe(
      false,
    );

    // Attacker stops. One full window of silence.
    advance(WINDOW_SECONDS * 1_000 + 1_000);

    const victim = await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
    expect(victim.allowed).toBe(true);
  });

  it("🚨 a victim stays locked out under a trickle that never reaches the cap", async () => {
    const { store, advance } = makeStore();

    // Step 1 — one short burst pushes the counter past the cap. Seconds of ordinary abuse.
    for (let i = 0; i < MAX_ATTEMPTS + 1; i++) {
      await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
      advance(500);
    }

    // Step 2 — the attacker drops to a TRICKLE: one request every 45 seconds. That is
    // 1.3 requests per 60s window against a limit of 10. The only property that matters
    // is that it arrives slightly faster than the window is long.
    const ATTACK_INTERVAL_MS = 45_000;
    const attackMinutes = 10;
    const ticks = Math.floor((attackMinutes * 60_000) / ATTACK_INTERVAL_MS);
    for (let i = 0; i < ticks; i++) {
      advance(ATTACK_INTERVAL_MS);
      await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
    }

    // Step 3 — the victim tries to log in. Ten minutes have passed; a window that expires
    // on its own schedule has drained ten times over, and holds at most a hit or two.
    advance(ATTACK_INTERVAL_MS);
    const victim = await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);

    expect(victim.allowed).toBe(true);
  });

  it("🚨 the counter grows without bound instead of resetting each window", async () => {
    // The mechanism behind the case above, asserted directly. Over ten minutes at one
    // request per 45s the counter should never exceed a couple of hits, because each
    // window starts from zero. A counter that keeps climbing is a window that never ends.
    const { store, advance } = makeStore();

    for (let i = 0; i < MAX_ATTEMPTS + 1; i++) {
      await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
      advance(500);
    }

    let last = { allowed: true, remaining: MAX_ATTEMPTS };
    for (let i = 0; i < 13; i++) {
      advance(45_000);
      last = await store.hitRateLimit(victimBucket, WINDOW_SECONDS, MAX_ATTEMPTS);
    }

    // `remaining` floors at 0, so read the count back through it: a healthy window leaves
    // most of the budget unspent.
    expect(last.remaining).toBeGreaterThan(0);
  });
});
