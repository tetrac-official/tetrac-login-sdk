// Tests for the non-breaking audit fixes from audits/zai-glm-52.md:
//   F3 — server-side PBKDF2 iteration floor (reject client-pinned counts out of band)
//   F8 — bounds-checked timingSafeEqual (no OOB read / NaN reliance)
// (F9 — purge ttc_biometric_reg on logout — is asserted in tests/react-hooks.test.tsx.)
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { deriveAuthPublicKey } from "../src/client/authKey";
import { timingSafeEqual } from "../src/core/crypto";

const APP_KEY = "ab".repeat(32);

function req(body: unknown): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function registerBody(extra: Record<string, unknown> = {}) {
  return {
    publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
    email: "floor@example.com",
    authPublicKey: deriveAuthPublicKey(APP_KEY),
    authMethod: "email",
    wallets: [],
    ...extra,
  };
}

describe("F3 — server PBKDF2 iteration floor", () => {
  // (NaN/Infinity can't survive JSON — they serialize to null and are treated as
  //  "absent" → legacy fallback — so the over-the-wire attack values are real numbers.)
  const reject: Array<[string, number]> = [
    ["1 (below floor)", 1],
    ["0", 0],
    ["1000000001 (above ceiling)", 1_000_000_001],
    ["600000.5 (non-integer)", 600_000.5],
  ];
  it.each(reject)("rejects pbkdf2Iterations=%s with 400", async (_label, iters) => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req(registerBody({ pbkdf2Iterations: iters })));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/pbkdf2Iterations/i);
  });

  const accept: Array<[string, number]> = [
    ["100000 (floor)", 100_000],
    ["600000 (default)", 600_000],
    ["1000000 (ceiling)", 1_000_000],
  ];
  it.each(accept)("accepts pbkdf2Iterations=%s (201)", async (_label, iters) => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req(registerBody({ pbkdf2Iterations: iters })));
    expect(res.status).toBe(201);
    expect((await res.json()).user.pbkdf2Iterations).toBe(iters);
  });

  it("rejects a non-number ('600000' string)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req(registerBody({ pbkdf2Iterations: "600000" })));
    expect(res.status).toBe(400);
  });

  it("still registers when pbkdf2Iterations is omitted (legacy/wallet path)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(req(registerBody()));
    expect(res.status).toBe(201);
    expect((await res.json()).user.pbkdf2Iterations).toBeUndefined();
  });
});

describe("F8 — timingSafeEqual is bounds-checked", () => {
  it("length mismatch returns a strict boolean false (no NaN/OOB reliance)", () => {
    expect(timingSafeEqual("a", "abc")).toBe(false);
    expect(timingSafeEqual("abc", "a")).toBe(false);
    expect(timingSafeEqual("", "x")).toBe(false);
    expect(typeof timingSafeEqual("a", "abc")).toBe("boolean");
  });

  it("still matches equal and rejects a same-length diff", () => {
    expect(timingSafeEqual("deadbeef", "deadbeef")).toBe(true);
    expect(timingSafeEqual("deadbeef", "deadbee0")).toBe(false);
  });
});
