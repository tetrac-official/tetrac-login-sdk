// The shipped security posture, pinned.
//
// Every value here is a DECISION, and most of them are the difference between a safe
// out-of-the-box deployment and an unsafe one. Nothing else in the suite asserts them as a
// set: `sessionTtlSeconds` moved 4h → 24h and no test would have noticed either way.
//
// This file is deliberately brittle. A failure is not a bug — it means a default moved, and
// the question to answer is "was that intended, and does the reasoning below still hold?".
// Update the expectation AND the comment together, or revert the change.
import { DEFAULT_CONFIG, PBKDF2_ITERATIONS, resolveConfig } from "../src/core/config";

describe("shipped defaults — session and challenge lifetime", () => {
  it("sessions last 24h", () => {
    // The TTL is the BACKSTOP, not the revocation path: every login revokes the previous
    // token, and verifySession requires the presented hash to be the record's current
    // pointer, so a leaked token dies at the owner's next sign-in rather than at expiry.
    expect(DEFAULT_CONFIG.sessionTtlSeconds).toBe(86_400);
  });

  it("challenges last 5 minutes", () => {
    // Long enough for a hardware wallet confirmation, short enough that the accumulated
    // set drains on its own — challenges are per-value now, so TTL is what bounds them.
    expect(DEFAULT_CONFIG.challengeTtlSeconds).toBe(300);
  });
});

describe("shipped defaults — anti-abuse", () => {
  it("general rate limit is 10 per 60s", () => {
    expect(DEFAULT_CONFIG.rateLimit).toEqual({ windowSeconds: 60, maxAttempts: 10 });
  });

  it("🚨 account creation is capped at 2 per 60s, deployment-wide", () => {
    // The ONE bucket with no key an attacker can rotate. Every other bucket is keyed on an
    // email or public key from the request body, so a fresh keypair per request is a fresh
    // counter — which is how an anonymous client used to mint unbounded permanent records.
    expect(DEFAULT_CONFIG.accountCreationRateLimit).toEqual({ windowSeconds: 60, maxAttempts: 2 });
  });

  it("🚨 proxy headers are NOT trusted by default", () => {
    // Correct-by-default: x-forwarded-for is caller-supplied unless a proxy you operate sets
    // it, and trusting it blindly is worse than skipping the per-IP limit. The cost is that
    // there is no requester identity, so createAuthHandlers WARNS about it at boot
    // (no_requester_identity) rather than leaving the trade-off silent.
    expect(DEFAULT_CONFIG.trustProxyHeaders).toBe(false);
    expect(DEFAULT_CONFIG.trustedProxyHops).toBe(0);
  });

  it("🚨 appId is unrestricted by default, which is why boot warns about it", () => {
    // No allowlist means any well-formed appId mints a namespace. Left as-is deliberately —
    // a required allowlist would break every single-app deployment that relies on the
    // config.appId fallback — and surfaced as a boot warning instead.
    expect(DEFAULT_CONFIG.allowedAppIds).toBeUndefined();
  });
});

describe("shipped defaults — key derivation", () => {
  it("securityLevel 2 = 600k PBKDF2 iterations (OWASP 2023 minimum)", () => {
    expect(DEFAULT_CONFIG.securityLevel).toBe(2);
    expect(PBKDF2_ITERATIONS[DEFAULT_CONFIG.securityLevel]).toBe(600_000);
  });

  it("the iteration ladder is monotonic and floors at 100k", () => {
    // The server bounds-checks a client-supplied count to [100k, 1M]; these are those bounds.
    expect(PBKDF2_ITERATIONS[1]).toBe(100_000);
    expect(PBKDF2_ITERATIONS[3]).toBe(1_000_000);
    expect(PBKDF2_ITERATIONS[1]).toBeLessThan(PBKDF2_ITERATIONS[2]);
    expect(PBKDF2_ITERATIONS[2]).toBeLessThan(PBKDF2_ITERATIONS[3]);
  });

  it("🚨 appId defaults to 'ttc', which provides NO cross-app isolation", () => {
    // Kept so the SDK works out of the box; the boot warning (default_app_id) is what makes
    // it a conscious choice rather than an accident.
    expect(DEFAULT_CONFIG.appId).toBe("ttc");
  });
});

describe("shipped defaults — the browser vault", () => {
  it("auto-locks after 15s idle, and on tab hide", () => {
    expect(DEFAULT_CONFIG.autoLockMs).toBe(15_000);
    expect(DEFAULT_CONFIG.lockOnHide).toBe(true);
  });

  it("🚨 revealing a secret requires a fresh re-auth ceremony", () => {
    // Reveal must never read the ambient unlocked key — it derives a one-time key from a
    // fresh ceremony. Flipping this to false silently removes the friction that makes an
    // export deliberate.
    expect(DEFAULT_CONFIG.revealRequiresReauth).toBe(true);
  });

  it("session→User-Agent binding is off by default", () => {
    // Coarse and opt-in: a UA string changes on browser update, which would log users out.
    expect(DEFAULT_CONFIG.bindSessionToUserAgent).toBe(false);
  });
});

describe("origin is required and normalized", () => {
  it("🚨 resolveConfig THROWS without an origin outside a browser", () => {
    // Not a default — deliberately absent from DEFAULT_CONFIG (`Omit<AuthConfig, "origin">`).
    // A wallet signature that verifies against nothing in particular is worse than a boot
    // failure, and origin is app-key derivation input, so there is no safe value to guess.
    expect(() => resolveConfig({})).toThrow(/origin is required/i);
  });

  it("normalizes case and trailing slashes so client and server agree byte-for-byte", () => {
    // Both sides build the signed message from this; disagreement fails every wallet login.
    expect(resolveConfig({ origin: "HTTPS://App.Example/" }).origin).toBe("https://app.example");
    expect(resolveConfig({ origin: " https://app.example// " }).origin).toBe("https://app.example");
  });
});

describe("key prefixes are disjoint", () => {
  it("no prefix is a prefix of another", () => {
    // Session keys are keyed by a token DIGEST and pubKey keys by an attacker-chosen public
    // key. If one namespace could be reached through the other, a crafted public key could
    // collide with a session token.
    const prefixes = Object.values(DEFAULT_CONFIG.keyPrefixes);
    for (const a of prefixes) {
      for (const b of prefixes) {
        if (a !== b) expect(a.startsWith(b)).toBe(false);
      }
    }
  });

  it("every prefix ends with the ':' separator", () => {
    for (const p of Object.values(DEFAULT_CONFIG.keyPrefixes)) expect(p.endsWith(":")).toBe(true);
  });
});
