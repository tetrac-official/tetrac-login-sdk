// Audit 2026-08-08 F-2 — /register must not let an unauthenticated attacker lock a named
// victim out of sign-in.
//
// The register bucket is keyed on a CALLER-SUPPLIED email, and the client's "auto" mode
// sends every returning user through /register (falling back to /login only on 409).
// Charging the bucket on ARRIVAL meant an attacker sending junk register requests for a
// victim's email filled that bucket with free rejects; the victim's own /register then
// 429'd, which the auto flow treats as terminal — the fallback to /login never ran.
//
// Fix: charge on FAILURE, exactly as /login does. A returning user's 409 costs nothing,
// and only a request that fails to prove possession feeds the counter — so a legitimate
// user with a valid proof is never throttled by an attacker's failures.
import { Keypair } from "@solana/web3.js";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail, loginEmail, jreq } from "./_auth-helpers";

const ORIGIN = "https://test.example";
const APP_KEY = "ab".repeat(32);
const freshKey = () => Keypair.generate().publicKey.toBase58();
const BAD_SIG = "ab".repeat(64);

function handlers(over: Record<string, unknown> = {}) {
  return createAuthHandlers({
    storage: new MemoryAdapter(),
    config: { origin: ORIGIN, rateLimit: { windowSeconds: 60, maxAttempts: 3 }, ...over },
    onWarning: () => {},
  });
}

describe("F-2 — a register flood on a victim's email does not lock the victim out", () => {
  it("🚨 the victim can still sign in (register→409→login) after an attacker's burst", async () => {
    const h = handlers();
    await registerEmail(h, { publicKey: "victim", email: "victim@test.com", appKey: APP_KEY });

    // Attacker names the victim's email with fresh keys and junk signatures. Each is a
    // 409 (email already registered) and — post-fix — costs the register bucket nothing.
    const attacker: number[] = [];
    for (let i = 0; i < 12; i++) {
      const res = await h.register(
        jreq({
          publicKey: freshKey(),
          email: "victim@test.com",
          authMethod: "wallet",
          signature: BAD_SIG,
          challenge: "cd".repeat(32),
        }),
      );
      attacker.push(res.status);
    }
    expect(attacker.every((s) => s === 409)).toBe(true);

    // The victim's normal auto sign-in: /register with a fresh keypair collides on email
    // (409, not 429), then /login succeeds.
    const reReg = await registerEmail(h, {
      publicKey: "victim-retry",
      email: "victim@test.com",
      appKey: APP_KEY,
    });
    expect(reReg.status).toBe(409);

    const login = await loginEmail(h, { email: "victim@test.com", appKey: APP_KEY });
    expect(login.status).toBe(200);
  });
});

describe("F-2 — the register limiter still engages, just on failure", () => {
  it("repeated FAILED registrations for one email are eventually throttled", async () => {
    const h = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 3 } });

    // Unregistered email, so no email-collision short-circuit: each request reaches the
    // signature check, fails it, and charges the register bucket keyed on the email.
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await h.register(
        jreq({
          publicKey: freshKey(),
          email: "target@test.com",
          authMethod: "wallet",
          signature: BAD_SIG,
          challenge: "cd".repeat(32),
        }),
      );
      statuses.push(res.status);
    }

    // First maxAttempts fail 401 (bad signature); the bucket then trips to 429.
    expect(statuses.slice(0, 3)).toEqual([401, 401, 401]);
    expect(statuses.slice(3)).toContain(429);
  });

  it("a valid registration is NEVER throttled by prior failures on the same email", async () => {
    const h = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 2 } });

    // Exhaust the failure bucket for this email.
    for (let i = 0; i < 5; i++) {
      await h.register(
        jreq({
          publicKey: freshKey(),
          email: "newuser@test.com",
          authMethod: "wallet",
          signature: BAD_SIG,
          challenge: "cd".repeat(32),
        }),
      );
    }

    // A genuine signup for that same email still goes through — success is not charged.
    const res = await registerEmail(h, {
      publicKey: "newuser",
      email: "newuser@test.com",
      appKey: APP_KEY,
    });
    expect(res.status).toBe(201);
  });
});
