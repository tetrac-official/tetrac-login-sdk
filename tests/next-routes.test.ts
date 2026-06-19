// Coverage for the Next.js App Router binding (src/next/routes.ts), previously 0%.
// It maps a catch-all `[...action]` to the SDK handlers and must: route every known
// POST/GET action, 404 unknown actions, and accept `ctx.params` as both a plain
// object (Next ≤14) and a Promise (Next 15+).
import { createNextAuthRoutes } from "../src/next/routes";
import { MemoryAdapter } from "../src/storage/memory";

function routes() {
  return createNextAuthRoutes({ storage: new MemoryAdapter() });
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
    const res = await POST(jreq("challenge", { publicKey: "k" }), ctx(["challenge"]));
    expect(res.status).toBe(200);
    expect((await res.json()).challenge).toHaveLength(64);
  });

  it("accepts params delivered as a Promise (Next 15+)", async () => {
    const { POST } = routes();
    const res = await POST(jreq("challenge", { publicKey: "k" }), ctx(["challenge"], true));
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

  it("404s an unknown POST action", async () => {
    const { POST } = routes();
    const res = await POST(jreq("nope", {}), ctx(["nope"]));
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("Not found");
  });

  it("routes a known GET action (search-wallet) to its handler", async () => {
    const { GET } = routes();
    const req = new Request("http://localhost/api/auth/search-wallet?publicKey=missing");
    const res = await GET(req, ctx(["search-wallet"]));
    expect(res.status).toBe(404); // handler's "Wallet not found" — dispatch worked
    expect((await res.json()).error).toMatch(/wallet not found/i);
  });

  it("404s an unknown GET action", async () => {
    const { GET } = routes();
    const res = await GET(new Request("http://localhost/api/auth/whatever"), ctx(["whatever"]));
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("Not found");
  });

  it("exposes the underlying handlers for direct use", () => {
    const r = routes();
    expect(typeof r.handlers.challenge).toBe("function");
    expect(typeof r.handlers.login).toBe("function");
  });
});
