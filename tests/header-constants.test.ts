// L-2 (audit.md) — the client and the server must name the wire headers identically.
//
// `AuthConfig` used to carry `sessionHeader` / `publicKeyHeader` / `appIdHeader`, and the
// SERVER honoured them (`req.headers.get(config.sessionHeader)`) while the CLIENT hardcoded
// the same three strings. Two sources of truth for one wire contract, so overriding any of
// them broke authentication silently: the server looked for the configured name, the client
// sent the literal, and every authenticated request returned 401 with nothing to explain it.
// The options were advertised and not honoured.
//
// They are now exported constants that both sides import, so they cannot drift.
import { Keypair } from "@solana/web3.js";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { AUTH_TOKEN_HEADER, PUBLIC_KEY_HEADER, APP_ID_HEADER, DEFAULT_CONFIG } from "../src/core/config";
import { registerEmail } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32);
const ORIGIN = "https://test.example";

describe("wire header names are shared constants", () => {
  it("keep their documented values (renaming one is a breaking wire change)", () => {
    expect(AUTH_TOKEN_HEADER).toBe("ttc-auth-token");
    expect(PUBLIC_KEY_HEADER).toBe("ttc-public-key");
    expect(APP_ID_HEADER).toBe("ttc-app-id");
  });

  it("🚨 are no longer configurable — the field that could desync them is gone", () => {
    // Guard against a well-meaning re-introduction. If someone adds these back to
    // AuthConfig, the client would have to honour them too or this bug returns.
    for (const dead of ["sessionHeader", "publicKeyHeader", "appIdHeader"]) {
      expect(DEFAULT_CONFIG).not.toHaveProperty(dead);
    }
  });

  it("🚨 a request built from the constants authenticates end-to-end", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: ORIGIN } });
    const publicKey = Keypair.generate().publicKey.toBase58();

    const reg = await registerEmail(h, {
      publicKey,
      email: "hdr@example.com",
      appKey: APP_KEY,
      wallets: [],
    });
    const { authToken } = await reg.json();

    // Exactly what the client's authHeaders() produces — same identifiers, not copies.
    const res = await h.userData(
      new Request("http://localhost/api/auth/user-data", {
        headers: {
          [AUTH_TOKEN_HEADER]: authToken,
          [PUBLIC_KEY_HEADER]: publicKey,
          [APP_ID_HEADER]: "ttc",
        },
      }),
    );
    expect(res.status).toBe(200);
  });

  it("the client's authHeaders() emits exactly those names", async () => {
    // session.ts is browser-only; give it the minimum it touches.
    const store = new Map<string, string>();
    Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
    Object.defineProperty(globalThis, "localStorage", {
      value: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
        clear: () => store.clear(),
      },
      configurable: true,
    });
    Object.defineProperty(globalThis, "document", {
      value: { addEventListener: () => {}, visibilityState: "visible" },
      configurable: true,
    });

    const { setSession, authHeaders, clearSession } = await import("../src/client/session");
    setSession({ publicKey: "PK", authToken: "TOKEN", appKey: APP_KEY });

    const sent = authHeaders();
    expect(sent[AUTH_TOKEN_HEADER]).toBe("TOKEN");
    expect(sent[PUBLIC_KEY_HEADER]).toBe("PK");
    // Nothing else — appId is added by AuthClient, which owns the resolved config.
    expect(Object.keys(sent).sort()).toEqual([AUTH_TOKEN_HEADER, PUBLIC_KEY_HEADER].sort());
    clearSession();
  });

  it("🚨 L-4: authenticated responses are never cacheable", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: ORIGIN } });
    const publicKey = Keypair.generate().publicKey.toBase58();
    const reg = await registerEmail(h, {
      publicKey,
      email: "cache@example.com",
      appKey: APP_KEY,
      wallets: [],
    });
    const { authToken } = await reg.json();

    // /user-data returns the full record, encrypted wallet blobs included. With no cache
    // directives the response is heuristically cacheable, so a shared cache keyed on URL
    // alone could hand one user's record to another.
    const res = await h.userData(
      new Request("http://localhost/api/auth/user-data", {
        headers: { [AUTH_TOKEN_HEADER]: authToken, [PUBLIC_KEY_HEADER]: publicKey },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");

    // Errors too — they are built by the same helper.
    expect((await h.userData(new Request("http://localhost/x"))).headers.get("cache-control")).toBe(
      "no-store",
    );
  });
});
