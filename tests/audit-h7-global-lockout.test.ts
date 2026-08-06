// H-7 — the "unknown" IP bucket was a global lockout vector.
//
// clientIp() used to return the literal string "unknown" when no proxy header was present,
// and rateLimited() gated on the IP bucket whenever config.trustProxyHeaders was true —
// with no check that a usable IP had actually been derived. A deployment that trusts its
// proxy but receives a request WITHOUT the headers (direct origin access, a health check, a
// bypassed CDN, local dev) put every caller into one shared bucket. At the default 10/60s,
// ordinary traffic locked out the entire deployment.
//
// The fix is the type: clientIp returns `string | null`, so "no usable IP" cannot be
// mistaken for an identity, and every caller has to decide what to do about it.
import { createAuthHandlers } from "../src/server/routes";
import { clientIp } from "../src/server/http";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail } from "./_auth-helpers";

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

describe("H-7 — no shared bucket when the IP is unusable", () => {
  it("🚨 clientIp returns null rather than a sentinel that can be keyed on", () => {
    const noHeaders = new Request("http://localhost/api/auth", { method: "POST" });
    // Trusted, but the request carries neither header — the exact production shape that
    // caused the outage.
    expect(clientIp(noHeaders, true, 0)).toBeNull();
    // Untrusted is null too: there is no trustworthy IP either way.
    expect(clientIp(noHeaders, false)).toBeNull();
  });

  it("🚨 trustProxyHeaders + NO proxy header does not lock out the deployment", async () => {
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 3 } });

    // Many DIFFERENT accounts, none carrying x-forwarded-for. Under the old sentinel every
    // one of these shared the "unknown" bucket, so request 4 onward was a 429 for everybody.
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) {
      statuses.push((await h.challenge(req({ email: `user${i}@test.com` }))).status);
    }
    expect(statuses.every((s) => s !== 429)).toBe(true);
  });

  it("🚨 one caller without a header cannot deny a different caller", async () => {
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 2 } });
    await registerEmail(h, { publicKey: PK, email: "victim@test.com", appKey: APP_KEY });

    // Attacker floods with no proxy header at all.
    for (let i = 0; i < 12; i++) await h.challenge(req({ email: "victim@test.com" }));

    // A legitimate request arriving THROUGH the proxy is unaffected.
    const ok = await h.challenge(req({ email: "victim@test.com" }, { "x-forwarded-for": "198.51.100.7" }));
    expect(ok.status).toBe(200);
  });

  it("still throttles per-IP when the header IS present", async () => {
    // The fix must not disable the control it is protecting — a real IP is still a bucket.
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      statuses.push(
        (await h.challenge(req({ email: `probe${i}@test.com` }, { "x-forwarded-for": "203.0.113.5" })))
          .status,
      );
    }
    expect(statuses).toContain(429);
  });

  it("🚨 header-less requests still fall back to the per-target bucket", async () => {
    // Regression guard: an earlier fix skipped the target bucket whenever
    // config.trustProxyHeaders was true. Combined with a header-less request that left
    // challenge issuance completely unthrottled. The decision must be made per REQUEST
    // (did we get an IP?), not per CONFIG (do we trust proxies?).
    const h = handlers({ trustProxyHeaders: true, rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(h, { publicKey: PK, email: "target@test.com", appKey: APP_KEY });

    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) {
      statuses.push((await h.challenge(req({ email: "target@test.com" }))).status);
    }
    expect(statuses).toContain(429);
  });
});
