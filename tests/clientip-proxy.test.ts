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
  it("ignores x-forwarded-for / x-real-ip entirely and returns 'unknown'", () => {
    const r = reqWith({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "9.9.9.9" });
    expect(clientIp(r, false)).toBe("unknown");
    expect(clientIp(r)).toBe("unknown"); // default arg
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

  it("falls back to x-real-ip when XFF is absent", () => {
    expect(clientIp(reqWith({ "x-real-ip": "7.7.7.7" }), true, 0)).toBe("7.7.7.7");
  });

  it("misconfigured hops past the start of the chain falls back (no crash, not a client value)", () => {
    // idx goes negative → fall through to x-real-ip, else "unknown". Never throws.
    expect(clientIp(reqWith({ "x-forwarded-for": "1.2.3.4" }), true, 5)).toBe("unknown");
    expect(clientIp(reqWith({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "7.7.7.7" }), true, 5)).toBe(
      "7.7.7.7",
    );
  });

  it("all-empty XFF falls back without crashing", () => {
    expect(clientIp(reqWith({ "x-forwarded-for": "  ,  , " }), true, 0)).toBe("unknown");
  });
});

describe("rate limiting becomes per-SOURCE when trustProxyHeaders is true", () => {
  it("one source IP shares a bucket across different target publicKeys (per-source throttle)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { trustProxyHeaders: true, rateLimit: { maxAttempts: 2, windowSeconds: 60 } },
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
      config: { trustProxyHeaders: true, rateLimit: { maxAttempts: 1, windowSeconds: 60 } },
    });
    const ch = (pk: string, ip: string) =>
      h.challenge(challengeReq({ publicKey: pk }, { "x-forwarded-for": ip }));
    expect((await ch("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "1.1.1.1")).status).toBe(200);
    expect((await ch("AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "1.1.1.1")).status).toBe(429); // same IP + same target → trips
    expect((await ch("9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu", "2.2.2.2")).status).toBe(200); // different IP → fresh
  });
});
