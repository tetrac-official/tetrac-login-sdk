// §6 candidate — type confusion on request fields, promoted to a fix.
//
// The body is JSON.parse output, so a field TypeScript calls `string` can be anything at
// runtime. Two coercion traps combined:
//
//   • `EMAIL_RE.test(["a@b.co"])` is TRUE — RegExp stringifies its argument.
//   • `["a@b.co"].length` is 1, so the ≤320 bound passed too.
//
// An array therefore cleared BOTH checks and reached normalizeEmail(), where
// `.toLowerCase()` does not exist on an array. An unauthenticated POST became a framework
// 500 with a stack — reachable on /challenge, /login, and /register.
//
// Every validator now type-checks first. These cases pin that: a non-string must be a clean
// 400, never a throw.
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { Keypair } from "@solana/web3.js";
import { deriveAuthPublicKey } from "../src/client/authKey";
import { proofFor, jreq } from "./_auth-helpers";

function h() {
  return createAuthHandlers({
    storage: new MemoryAdapter(),
    config: { origin: "https://test.example" },
    onWarning: () => {},
  });
}

function post(body: unknown): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** The shapes JSON can carry where a string was expected. */
const NON_STRINGS: Array<[string, unknown]> = [
  ["array", ["a@b.co"]],
  ["nested array", [["a@b.co"]]],
  ["number", 12345],
  ["object", { toString: "a@b.co" }],
  ["boolean", true],
  ["null-ish object", { length: 5 }],
];

describe("🚨 a non-string email is a 400, never a 500", () => {
  it.each(NON_STRINGS)("/challenge rejects a %s email", async (_label, email) => {
    const res = await h().challenge(post({ email }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/Invalid email/i);
  });

  it.each(NON_STRINGS)("/login rejects a %s email", async (_label, email) => {
    const res = await h().login(post({ email, signature: "ab".repeat(64), challenge: "a".repeat(64) }));
    expect(res.status).toBe(400);
  });

  it("the array that used to pass BOTH the regex and the length bound", async () => {
    // Documented explicitly because it is the exact bypass: RegExp coerces, and Array#length
    // is the element count, not a character count.
    expect(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(["a@b.co"] as unknown as string)).toBe(true);
    expect((["a@b.co"] as unknown as string).length).toBe(1);

    const res = await h().challenge(post({ email: ["a@b.co"] }));
    expect(res.status).toBe(400);
  });
});

describe("🚨 a non-string publicKey is a 400, never a 500", () => {
  it.each(NON_STRINGS)("/challenge rejects a %s publicKey", async (_label, publicKey) => {
    const res = await h().challenge(post({ publicKey }));
    expect(res.status).toBe(400);
  });

  it("/register rejects a non-string publicKey", async () => {
    const res = await h().register(post({ publicKey: ["AKkz"], email: "a@b.co" }));
    expect(res.status).toBe(400);
  });
});

describe("🚨 a non-string appId is a 400, never a 500", () => {
  it.each(NON_STRINGS)("/challenge rejects a %s appId", async (_label, appId) => {
    const res = await h().challenge(post({ appId, email: "a@b.co" }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/Invalid appId/i);
  });

  it("an object appId cannot reach a storage key", async () => {
    // appId is concatenated into every per-user key. A non-string reaching that
    // concatenation would stringify to "[object Object]" and silently share a namespace.
    const res = await h().challenge(post({ appId: { toString: () => "evil" }, email: "a@b.co" }));
    expect(res.status).toBe(400);
  });
});

describe("🚨 a non-string authPublicKey is a 400, never a 500", () => {
  it("/register rejects it", async () => {
    const res = await h().register(
      post({
        publicKey: "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa",
        email: "a@b.co",
        authMethod: "email",
        authPublicKey: ["ab".repeat(32)],
        wallets: [],
      }),
    );
    expect(res.status).toBe(400);
  });
});

describe("🚨 a non-string / unknown authMethod is a 400, never persisted (F-3)", () => {
  const PK = "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa";
  const BAD: Array<[string, unknown]> = [
    ["array", ["wallet"]],
    ["number", 1],
    ["boolean", true],
    ["object", { evil: true }],
    ["unknown string", "admin"],
    ["oversized string", "x".repeat(60_000)],
  ];
  it.each(BAD)("/register rejects a %s authMethod", async (_label, authMethod) => {
    const res = await h().register(
      post({ publicKey: PK, email: "a@b.co", authMethod, authPublicKey: "ab".repeat(32) }),
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/Invalid authMethod/i);
  });

  it("a valid non-default authMethod is accepted and round-trips unchanged", async () => {
    // Guard against over-strict validation: "biometric" is a member of the union and must
    // persist as given, not be coerced to the "email" default.
    const handlers = h();
    const kp = Keypair.generate();
    const proof = await proofFor(handlers, kp);
    const res = await handlers.register(
      jreq({
        publicKey: kp.publicKey.toBase58(),
        email: "bio@b.co",
        authMethod: "biometric",
        authPublicKey: deriveAuthPublicKey("ab".repeat(32)),
        wallets: [],
        ...proof,
      }),
    );
    expect(res.status).toBe(201);
    expect((await res.json()).user.authMethod).toBe("biometric");
  });
});

describe("no handler throws on a hostile body", () => {
  it("every POST route answers rather than rejecting the promise", async () => {
    // The property that matters operationally: a malformed body is a client error, so it
    // must never surface as an unhandled rejection the framework renders as a 500.
    const hostile = {
      appId: ["x"],
      email: { a: 1 },
      publicKey: 42,
      authPublicKey: null,
      signature: [],
      challenge: {},
      wallets: "not-an-array",
    };
    const handlers = h();
    for (const route of [
      handlers.challenge,
      handlers.register,
      handlers.login,
      handlers.loginWallet,
      handlers.connectWallet,
    ]) {
      const res = await route(post(hostile));
      expect(res).toBeInstanceOf(Response);
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
    }
  });
});
