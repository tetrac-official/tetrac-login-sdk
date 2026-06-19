// WI-23 — optional session→User-Agent binding (config.bindSessionToUserAgent).
// Default OFF preserves the plain `session:{token}` -> publicKey value; when ON, a
// session is pinned to SHA-256(User-Agent) and a request with a different/missing UA
// is rejected. Enforcement is per-session: a bound session stays bound even if the
// flag is later disabled.
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { hashUserAgent } from "../src/core/crypto";
import { deriveAuthPublicKey } from "../src/client/authKey";

const APP_KEY = "ab".repeat(32);
const PUBKEY = "SoLfp11111111111111111111111111111111111111";
const EMAIL = "fp@example.com";
const UA_A = "Mozilla/5.0 (Macintosh) AppleWebKit/537 Chrome/120";
const UA_B = "Mozilla/5.0 (Windows NT 10.0) Firefox/121";

function reqWith(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function register(h: ReturnType<typeof createAuthHandlers>, ua?: string) {
  return h.register(
    reqWith(
      {
        publicKey: PUBKEY,
        email: EMAIL,
        authPublicKey: deriveAuthPublicKey(APP_KEY),
        authMethod: "email",
        wallets: [],
      },
      ua ? { "user-agent": ua } : {},
    ),
  );
}

function userData(h: ReturnType<typeof createAuthHandlers>, token: string, publicKey: string, ua?: string) {
  return h.userData(
    reqWith(
      {},
      { "ttc-auth-token": token, "ttc-public-key": publicKey, ...(ua ? { "user-agent": ua } : {}) },
    ),
  );
}

describe("session→User-Agent binding (WI-23)", () => {
  it("default (off): the stored value is the bare publicKey and the UA is ignored", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const { authToken, publicKey } = await (await register(h, UA_A)).json();

    expect(await storage.get(`session:ttc:${authToken}`)).toBe(publicKey); // no "|fingerprint"
    // A totally different UA still verifies — binding is off.
    expect((await userData(h, authToken, publicKey, UA_B)).status).toBe(200);
  });

  it("on: pins the session to SHA-256(UA) and accepts the matching UA", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { bindSessionToUserAgent: true } });
    const { authToken, publicKey } = await (await register(h, UA_A)).json();

    expect(await storage.get(`session:ttc:${authToken}`)).toBe(`${publicKey}|${hashUserAgent(UA_A)}`);
    expect((await userData(h, authToken, publicKey, UA_A)).status).toBe(200);
  });

  it("on: rejects a different User-Agent (401)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { bindSessionToUserAgent: true } });
    const { authToken, publicKey } = await (await register(h, UA_A)).json();

    expect((await userData(h, authToken, publicKey, UA_B)).status).toBe(401);
  });

  it("on: rejects a request with no User-Agent (401)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { bindSessionToUserAgent: true } });
    const { authToken, publicKey } = await (await register(h, UA_A)).json();

    expect((await userData(h, authToken, publicKey)).status).toBe(401); // no UA header
  });

  it("a session bound while the flag was on stays enforced after the flag is disabled", async () => {
    const storage = new MemoryAdapter();
    const bound = createAuthHandlers({ storage, config: { bindSessionToUserAgent: true } });
    const { authToken, publicKey } = await (await register(bound, UA_A)).json();

    // New handler over the SAME storage with binding now OFF — the stored fingerprint
    // must still be enforced (disabling the flag never un-binds live sessions).
    const unbound = createAuthHandlers({ storage, config: { bindSessionToUserAgent: false } });
    expect((await userData(unbound, authToken, publicKey, UA_A)).status).toBe(200);
    expect((await userData(unbound, authToken, publicKey, UA_B)).status).toBe(401);
  });
});
