// v0.5.0 — the NEGATIVE CONTROL for the conformance suite.
//
// A conformance suite that cannot fail is worthless: 24 green checkmarks would give
// exactly as much confidence as 24 empty functions. So this file implements the store a
// competent engineer plausibly writes on their first attempt — every bug here is one the
// SDK's own docs warn about — and asserts the suite CATCHES each one.
//
// This is what makes the suite the acceptance bar rather than decoration.
import { authStoreConformanceCases } from "../src/storage/conformance";
import type { AuthStore, RateLimitBucket, RateLimitResult, SessionValue } from "../src/storage/store";
import type { UserData } from "../src/core/types";

/** Yield to the microtask queue, so two "concurrent" callers really do interleave. */
const tick = () => Promise.resolve();

/**
 * The naive store. Every one of these is a mistake that looks completely reasonable:
 *
 *  1. The rate-limit counter never expires        → PERMANENT LOCKOUT
 *  2. takeChallenge is get-then-delete, not atomic → CHALLENGE REPLAY
 *  3. Reads ignore expiry (a "reaper will handle it") → EXPIRED SESSIONS ACCEPTED
 *  4. The email index is read-modify-write         → LOST REGISTRATION
 *  5. Keys are case-folded (a case-insensitive collation) → CROSS-TENANT / CROSS-ACCOUNT COLLISION
 */
class NaiveAuthStore implements AuthStore {
  private users = new Map<string, UserData>();
  private emailIdx = new Map<string, Record<string, string>>();
  private challenges = new Map<string, { value: string; expiresAt: number }>();
  private sessions = new Map<string, { value: SessionValue; expiresAt: number }>();
  private counters = new Map<string, number>();

  // BUG 5: case-folded key — i.e. what a default MySQL collation does for you.
  private userKey(appId: string, publicKey: string): string {
    return `${appId}:${publicKey}`.toLowerCase();
  }

  async getUser(appId: string, publicKey: string): Promise<UserData | null> {
    return this.users.get(this.userKey(appId, publicKey)) ?? null;
  }

  async putUser(user: UserData): Promise<void> {
    this.users.set(this.userKey(user.appId, user.publicKey), user);
    if (user.email) {
      // BUG 4: read the whole index, merge in JS, write it back. Two concurrent
      // registrations of the same email under different appIds race, and one is lost.
      const key = user.email.toLowerCase().trim();
      const current = this.emailIdx.get(key) ?? {};
      await tick(); // the window in which the other writer reads the same snapshot
      this.emailIdx.set(key, { ...current, [user.appId]: user.publicKey });
    }
  }

  async getPublicKeyByEmail(appId: string, email: string): Promise<string | null> {
    return this.emailIdx.get(email.toLowerCase().trim())?.[appId] ?? null;
  }

  async putChallenge(appId: string, publicKey: string, challenge: string, ttl: number): Promise<void> {
    this.challenges.set(`${appId}:${publicKey}`, {
      value: challenge,
      expiresAt: Date.now() + ttl * 1000,
    });
  }

  async takeChallenge(appId: string, publicKey: string): Promise<string | null> {
    const k = `${appId}:${publicKey}`;
    // BUG 2: get, then delete — not one atomic operation.
    // BUG 3: no expiry check on the read path.
    const hit = this.challenges.get(k);
    if (!hit) return null;
    await tick(); // another consumer reads the SAME challenge here
    this.challenges.delete(k);
    return hit.value;
  }

  async putSession(appId: string, tokenHash: string, value: SessionValue, ttl: number): Promise<void> {
    this.sessions.set(`${appId}:${tokenHash}`, { value, expiresAt: Date.now() + ttl * 1000 });
  }

  async getSession(appId: string, tokenHash: string): Promise<SessionValue | null> {
    // BUG 3: expiry is "handled by the reaper". It is not — the value is still readable.
    return this.sessions.get(`${appId}:${tokenHash}`)?.value ?? null;
  }

  async deleteSession(appId: string, tokenHash: string): Promise<void> {
    this.sessions.delete(`${appId}:${tokenHash}`);
  }

  async hitRateLimit(
    bucket: RateLimitBucket,
    _windowSeconds: number,
    maxAttempts: number,
  ): Promise<RateLimitResult> {
    // BUG 1: the counter has no window. It only ever goes up. Once an identifier trips
    // the limit it is throttled FOREVER — a permanent, self-inflicted denial of service
    // that no smoke test catches, because it only appears after a window elapses.
    const k = `${bucket.endpoint}:${bucket.appId ?? ""}:${bucket.identifier}`;
    const n = (this.counters.get(k) ?? 0) + 1;
    this.counters.set(k, n);
    return { allowed: n <= maxAttempts, remaining: Math.max(0, maxAttempts - n) };
  }
}

describe("conformance suite — negative control (it must FAIL on a naive store)", () => {
  // The suite's own clock cannot help a store that ignores time, so let it really sleep;
  // TTLs in the expiry cases are 1s.
  const cases = authStoreConformanceCases(() => new NaiveAuthStore());

  // These are the failures that matter. Each maps to a documented hazard, and each is a
  // real, exploitable defect — not a style nit.
  const MUST_CATCH = [
    "rate limit: after the window elapses",
    "challenge: N concurrent takeChallenge",
    "challenge: an expired challenge is invisible",
    "session: an expired session is invisible",
    "email index: concurrent putUser",
    "isolation: tenants differing only in CASE",
    "isolation: public keys differing only in CASE",
  ];

  let failed: string[];

  beforeAll(async () => {
    failed = [];
    for (const c of cases) {
      await c.run().then(
        () => undefined,
        () => failed.push(c.name),
      );
    }
  }, 30_000);

  for (const needle of MUST_CATCH) {
    it(`catches: ${needle}`, () => {
      expect(failed.some((n) => n.includes(needle))).toBe(true);
    });
  }

  it("does not fail for spurious reasons — the naive store still passes the trivial cases", () => {
    // If EVERY case failed, the suite would be catching nothing in particular and the
    // assertions above would be vacuous.
    expect(failed.length).toBeLessThan(cases.length);
    expect(failed.some((n) => n.includes("absent challenge returns null"))).toBe(false);
  });
});
