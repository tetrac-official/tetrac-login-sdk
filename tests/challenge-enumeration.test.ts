// L-3 (enumeration oracle) and the M-1 residual (targeted lockout via the /challenge
// bucket). One root cause: with no trustworthy requester IP the anti-abuse buckets fall
// back to keying on the caller-supplied target, which both denies the target and makes a
// horizontal sweep invisible (each probed identifier gets its own counter).
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail } from "./_auth-helpers";
import { PBKDF2_ITERATIONS } from "../src/core/config";

const PK = "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa";
const APP_KEY = "ab".repeat(32);

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function handlers(config: Record<string, unknown> = {}) {
  return createAuthHandlers({
    storage: new MemoryAdapter(),
    config: { origin: "https://test.example", ...config },
    onWarning: () => {},
  });
}

describe("L-3 — /challenge is not an account-existence oracle", () => {
  it("🚨 a registered and an unregistered email are indistinguishable", async () => {
    const h = handlers();
    await registerEmail(h, { publicKey: PK, email: "known@test.com", appKey: APP_KEY });

    const known = await h.challenge(req({ email: "known@test.com" }));
    const unknown = await h.challenge(req({ email: "nobody@test.com" }));

    expect(known.status).toBe(200);
    expect(unknown.status).toBe(200);

    const [a, b] = [await known.json(), await unknown.json()];
    // Same keys — an omitted field would move the oracle one key over rather than close it.
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());
    expect(a.pbkdf2Iterations).toBe(b.pbkdf2Iterations);
    expect(b.challenge).toMatch(/^[0-9a-f]{64}$/);
  });

  it("the dummy carries the deployment's own iteration count, not a fixed constant", async () => {
    // A hardcoded value would disagree with a deployment on a non-default securityLevel
    // and become the tell itself.
    for (const level of [1, 2, 3] as const) {
      const h = handlers({ securityLevel: level });
      const res = await h.challenge(req({ email: "nobody@test.com" }));
      expect((await res.json()).pbkdf2Iterations).toBe(PBKDF2_ITERATIONS[level]);
    }
  });

  it("🚨 the dummy is never stored, so it cannot complete a login", async () => {
    const h = handlers();
    const res = await h.challenge(req({ email: "nobody@test.com" }));
    const { challenge } = await res.json();

    // Sign it with a well-formed but unrelated key — the shape a real client would send.
    const login = await h.login(req({ email: "nobody@test.com", challenge, signature: "ab".repeat(64) }));
    expect(login.status).not.toBe(200);
  });

  it("a fresh dummy every time, like a real challenge", async () => {
    const h = handlers();
    const seen = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const res = await h.challenge(req({ email: "nobody@test.com" }));
      seen.add((await res.json()).challenge);
    }
    // A stable per-email value would itself be the oracle: repeat the probe, compare.
    expect(seen.size).toBe(5);
  });

  it("a request naming NEITHER email nor publicKey is still a 400", async () => {
    // Malformed, not a probe — there is no identifier to be discreet about.
    const h = handlers();
    const res = await h.challenge(req({}));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("publicKey or email required");
  });
});

describe("M-1 residual — an attacker cannot spend the victim's /challenge budget", () => {
  it("🚨 with a trustworthy IP, a flood from one requester leaves the victim able to log in", async () => {
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 5 } });
    await registerEmail(h, { publicKey: PK, email: "victim@test.com", appKey: APP_KEY });

    // Attacker burns their OWN bucket naming the victim.
    const attacker = { "x-forwarded-for": "203.0.113.9" };
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      statuses.push((await h.challenge(req({ email: "victim@test.com" }, attacker))).status);
    }
    expect(statuses).toContain(429); // the abuser is throttled...

    // ...and the victim, on their own IP, is untouched.
    const victim = await h.challenge(
      req({ email: "victim@test.com" }, { "x-forwarded-for": "198.51.100.4" }),
    );
    expect(victim.status).toBe(200);
  });

  it("🚨 a horizontal sweep is throttled once a requester can be identified", async () => {
    // The point of requester-keying: the counter finally sees BREADTH. Per-target keying
    // gave each probed address its own counter, so N addresses cost N free requests.
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 5 } });
    const sweeper = { "x-forwarded-for": "203.0.113.77" };

    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) {
      statuses.push((await h.challenge(req({ email: `probe${i}@test.com` }, sweeper))).status);
    }
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
  });

  it("without a trustworthy IP it still falls back to the target bucket", async () => {
    // Not a regression — it is the only key available, and leaving issuance unbounded
    // would be worse. The boot warning is what tells the operator to fix the deployment.
    const h = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(h, { publicKey: PK, email: "fallback@test.com", appKey: APP_KEY });

    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      statuses.push((await h.challenge(req({ email: "fallback@test.com" }))).status);
    }
    expect(statuses).toContain(429);
  });

  it("the target bucket is NOT also charged when the IP bucket is", async () => {
    // Double-charging would leave the victim's counter drainable by an attacker even on a
    // correctly configured deployment — the whole point of the fix.
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 4 } });
    await registerEmail(h, { publicKey: PK, email: "shared@test.com", appKey: APP_KEY });

    // Each request comes from a DIFFERENT IP, so no IP bucket ever fills. If the target
    // bucket were still being charged, the shared email counter would 429.
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) {
      statuses.push(
        (await h.challenge(req({ email: "shared@test.com" }, { "x-forwarded-for": `203.0.113.${i}` })))
          .status,
      );
    }
    expect(statuses.every((s) => s === 200)).toBe(true);
  });
});

describe("the misconfiguration is announced at boot", () => {
  it("🚨 warns when trustProxyHeaders is false", () => {
    const seen: { code: string; message: string }[] = [];
    createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        appId: "noproxy.example",
        allowedAppIds: ["noproxy.example"],
      },
      onWarning: (w) => seen.push(w),
    });
    const w = seen.find((x) => x.code === "no_requester_identity");
    expect(w).toBeDefined();
    // Must name BOTH consequences, and must not read as "always turn this on".
    expect(w!.message).toMatch(/hold it out of login/);
    expect(w!.message).toMatch(/sweep/);
    expect(w!.message).toMatch(/Do NOT set it when the app is directly reachable/);
  });

  it("stays silent when a proxy is trusted", () => {
    const seen: { code: string }[] = [];
    createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        appId: "proxied.example",
        allowedAppIds: ["proxied.example"],
        trustProxyHeaders: true,
      },
      onWarning: (w) => seen.push(w),
    });
    expect(seen.map((w) => w.code)).not.toContain("no_requester_identity");
  });
});
