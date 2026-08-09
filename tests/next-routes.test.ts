// Coverage for the Next.js App Router binding (src/next/routes.ts), previously 0%.
// It maps a catch-all `[...action]` to the SDK handlers and must: route every known
// POST/GET action, REJECT unknown actions with 400, and accept `ctx.params` as both a plain
// object (Next ≤14) and a Promise (Next 15+).
import { createNextAuthRoutes } from "../src/next/routes";
import { MemoryAdapter } from "../src/storage/memory";

function routes() {
  return createNextAuthRoutes({ storage: new MemoryAdapter(), config: { origin: "https://test.example" } });
}

function ctx(action: string[], asPromise = false) {
  const params = { action };
  return { params: asPromise ? Promise.resolve(params) : params };
}

function jreq(url: string, body?: unknown): Request {
  return new Request(`http://localhost/api/auth/${url}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

describe("createNextAuthRoutes — action dispatch", () => {
  it("routes a known POST action (challenge) with plain params", async () => {
    const { POST } = routes();
    const res = await POST(
      jreq("challenge", { publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9" }),
      ctx(["challenge"]),
    );
    expect(res.status).toBe(200);
    expect((await res.json()).challenge).toHaveLength(64);
  });

  it("accepts params delivered as a Promise (Next 15+)", async () => {
    const { POST } = routes();
    const res = await POST(
      jreq("challenge", { publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9" }),
      ctx(["challenge"], true),
    );
    expect(res.status).toBe(200);
  });

  it("reaches the handler (not the dispatcher) for a wired action — register validates input", async () => {
    const { POST } = routes();
    const res = await POST(jreq("register", {}), ctx(["register"]));
    expect(res.status).toBe(400); // handler ran: "publicKey required" — proves it wasn't a dispatch 404
    expect((await res.json()).error).toMatch(/publicKey required/i);
  });

  it("routes logout", async () => {
    const { POST } = routes();
    const res = await POST(jreq("logout", {}), ctx(["logout"]));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("rejects an unknown POST action with 400, not 404", async () => {
    const { POST } = routes();
    const res = await POST(jreq("nope", {}), ctx(["nope"]));
    expect(res.status).toBe(400); // the ROUTE exists; the action segment names nothing
    expect((await res.json()).error).toMatch(/^Unknown auth action/);
  });

  it("routes a known GET action (search-wallet) to its handler", async () => {
    const { GET } = routes();
    const req = new Request(
      "http://localhost/api/auth/search-wallet?publicKey=9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu",
    );
    const res = await GET(req, ctx(["search-wallet"]));
    // Reaching the HANDLER is what this asserts: a valid, unregistered key answers
    // 200 { exists: false } — a successful search with no match, not a routing failure.
    expect(res.status).toBe(200);
    expect((await res.json()).exists).toBe(false);
  });

  it("rejects an unknown GET action with 400, not 404", async () => {
    const { GET } = routes();
    const res = await GET(new Request("http://localhost/api/auth/whatever"), ctx(["whatever"]));
    expect(res.status).toBe(400); // the ROUTE exists; the action segment names nothing
    expect((await res.json()).error).toMatch(/^Unknown auth action/);
  });

  it("exposes the underlying handlers for direct use", () => {
    const r = routes();
    expect(typeof r.handlers.challenge).toBe("function");
    expect(typeof r.handlers.login).toBe("function");
  });
});

// L-1 (audit.md) — the dispatch table must not resolve inherited properties.
//
// It was an object literal, so `postRoutes["constructor"]` walked Object.prototype, found
// the Object constructor, saw it as truthy and CALLED it as a handler. The route then
// returned `Object(req)` — a Request, not a Response — and `valueOf` / `hasOwnProperty`
// threw a raw TypeError because `this` was undefined. Unauthenticated requests became
// framework 500s with stacks where a clean rejection belonged. No real handler was ever
// reachable this way; the damage was noise that looked like an incident.
describe("createNextAuthRoutes — prototype-chain dispatch", () => {
  const INHERITED = [
    "constructor",
    "toString",
    "valueOf",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "__proto__",
  ];

  it("🚨 every inherited property name is rejected, not invoked", async () => {
    const { POST, GET } = routes();
    for (const name of INHERITED) {
      const post = await POST(jreq(name, {}), ctx([name]));
      expect(post).toBeInstanceOf(Response); // not Object(req), not a thrown TypeError
      expect(post.status).toBe(400);
      expect((await post.json()).error).toMatch(/^Unknown auth action/);

      const get = await GET(new Request(`http://localhost/api/auth/${name}`), ctx([name]));
      expect(get).toBeInstanceOf(Response);
      expect(get.status).toBe(400);
    }
  });

  it("the rejection names what WAS expected, so a typo is self-diagnosing", async () => {
    const { POST } = routes();
    const res = await POST(jreq("loginn", {}), ctx(["loginn"]));
    const { error } = await res.json();
    expect(error).toContain('"loginn"');
    expect(error).toContain("login-wallet"); // the valid set is listed
  });

  it("the unknown-action status is configurable for hosts that forbid a bare 400", async () => {
    const { POST } = createNextAuthRoutes({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
      unknownActionStatus: 422,
    });
    const res = await POST(jreq("nope", {}), ctx(["nope"]));
    expect(res.status).toBe(422);
  });
});

// The SDK never answers 404. In a web context it reads as "page not found", so it
// misrepresents every case it was used for here: an unknown action segment (the route
// exists — 400), a search with no match (the query ran — 200 { exists: false }), and a
// verified wallet with no account yet (well-formed and authenticated — 422).
describe("no endpoint answers 404", () => {
  it("🚨 unknown actions, empty searches and unregistered wallets all avoid 404", async () => {
    const { POST, GET, handlers } = routes();

    // 1. Unknown action segment.
    expect((await POST(jreq("nope", {}), ctx(["nope"]))).status).toBe(400);
    expect((await GET(new Request("http://localhost/api/auth/nope"), ctx(["nope"]))).status).toBe(400);

    // 2. A search that matches nothing.
    const search = await handlers.searchWallet(
      new Request(
        "http://localhost/api/auth/search-wallet?publicKey=9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu",
      ),
    );
    expect(search.status).toBe(200);
    expect((await search.json()).exists).toBe(false);
  });

  it("🚨 a VERIFIED wallet with no account gets 422, not 404", async () => {
    const { Keypair } = await import("@solana/web3.js");
    const nacl = (await import("tweetnacl")).default;
    const { walletLoginMessage } = await import("../src/core/index");
    const { handlers } = routes();

    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await handlers.challenge(jreq("challenge", { publicKey }))).json();
    const signature = Array.from(
      nacl.sign.detached(
        new TextEncoder().encode(walletLoginMessage(challenge, "https://test.example")),
        kp.secretKey,
      ),
      (b) => b.toString(16).padStart(2, "0"),
    ).join("");

    // The signature is genuine — the caller really does hold this key. There is just no
    // account yet, which is neither a bad request nor a failed credential.
    const res = await handlers.loginWallet(jreq("login-wallet", { publicKey, signature, challenge }));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toBe("Wallet not registered");
  });
});
