// WI-4b — clientIp() proxy-hop selection + per-source rate limiting when trusted.
// Covers the gap the adversarial review flagged: trustedProxyHops had zero tests.
import { clientIp } from "../src/server/http";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";

function reqWith(headers: Record<string, string>): Request {
  return new Request("http://localhost/api/auth", { method: "POST", headers });
}
function challengeReq(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("clientIp() — untrusted (default)", () => {
  it("ignores x-forwarded-for / x-real-ip entirely and returns null", () => {
    const r = reqWith({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "9.9.9.9" });
    expect(clientIp(r, false)).toBeNull();
    expect(clientIp(r)).toBeNull(); // default arg
  });
});

describe("clientIp() — trusted, rightmost-after-hops", () => {
  it("single proxy (hops 0) returns the only XFF entry", () => {
    expect(clientIp(reqWith({ "x-forwarded-for": "1.2.3.4" }), true, 0)).toBe("1.2.3.4");
  });

  it("ignores a client-spoofed LEFTMOST entry (rightmost is proxy-appended)", () => {
    // Attacker prepends 9.9.9.9; the trusted proxy appended the real 1.2.3.4 on the right.
    expect(clientIp(reqWith({ "x-forwarded-for": "9.9.9.9, 1.2.3.4" }), true, 0)).toBe("1.2.3.4");
  });

  it("skips trustedProxyHops entries from the right", () => {
    const xff = "1.1.1.1, 2.2.2.2, 3.3.3.3";
    expect(clientIp(reqWith({ "x-forwarded-for": xff }), true, 0)).toBe("3.3.3.3");
    expect(clientIp(reqWith({ "x-forwarded-for": xff }), true, 1)).toBe("2.2.2.2");
    expect(clientIp(reqWith({ "x-forwarded-for": xff }), true, 2)).toBe("1.1.1.1");
  });

  it("tolerates whitespace and trailing/empty entries", () => {
    expect(clientIp(reqWith({ "x-forwarded-for": "  1.1.1.1 , 2.2.2.2 , " }), true, 0)).toBe("2.2.2.2");
  });

  it("falls back to x-real-ip when XFF is absent AND hops is 0 (single trusted edge)", () => {
    expect(clientIp(reqWith({ "x-real-ip": "7.7.7.7" }), true, 0)).toBe("7.7.7.7");
  });

  it("🚨 does NOT consult x-real-ip when XFF is absent but hops > 0 (F-6)", () => {
    // With hops > 0 the operator declared a multi-proxy chain; a lone x-real-ip did not
    // traverse it, so trusting it would undo the configured hop count.
    expect(clientIp(reqWith({ "x-real-ip": "7.7.7.7" }), true, 1)).toBeNull();
  });

  it("🚨 a chain SHORTER than the configured hops is 'no trustworthy IP', not x-real-ip (F-6)", () => {
    // idx goes negative → the request did not traverse the expected proxy chain. Returning
    // x-real-ip there — a header the caller controls in that scenario — silently undid
    // trustedProxyHops and let the caller pick their own bucket. Now: null, never a fallback.
    expect(clientIp(reqWith({ "x-forwarded-for": "1.2.3.4" }), true, 5)).toBeNull();
    expect(clientIp(reqWith({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "7.7.7.7" }), true, 5)).toBeNull();
  });

  it("all-empty XFF is 'no trustworthy IP' and never falls through to a client header", () => {
    expect(clientIp(reqWith({ "x-forwarded-for": "  ,  , " }), true, 0)).toBeNull();
    // Even with x-real-ip present: a present-but-empty XFF still means the chain was not
    // traversed as configured, so x-real-ip is not consulted.
    expect(clientIp(reqWith({ "x-forwarded-for": "  ,  , ", "x-real-ip": "7.7.7.7" }), true, 0)).toBeNull();
  });
});

describe("rate limiting becomes per-SOURCE when trustProxyHeaders is true", () => {
  it("one source IP shares a bucket across different target publicKeys (per-source throttle)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        trustProxyHeaders: true,
        // The per-IP bucket has its own config now (F-7); size THAT to exercise it.
        ipRateLimit: { maxAttempts: 2, windowSeconds: 60 },
      },
    });
    const fromIp = (pk: string) =>
      h.challenge(challengeReq({ publicKey: pk }, { "x-forwarded-for": "1.2.3.4" }));
    // Same source IP, DIFFERENT targets — the per-source IP bucket still trips.
    expect((await fromIp("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9")).status).toBe(200);
    expect((await fromIp("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu")).status).toBe(200);
    expect((await fromIp("GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse")).status).toBe(429); // IP bucket exhausted
  });

  it("different source IPs get independent buckets", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        trustProxyHeaders: true,
        ipRateLimit: { maxAttempts: 1, windowSeconds: 60 },
      },
    });
    const ch = (pk: string, ip: string) =>
      h.challenge(challengeReq({ publicKey: pk }, { "x-forwarded-for": ip }));
    expect((await ch("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "1.1.1.1")).status).toBe(200);
    expect((await ch("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "1.1.1.1")).status).toBe(429); // same IP + same target → trips
    expect((await ch("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu", "2.2.2.2")).status).toBe(200); // different IP → fresh
  });
});
