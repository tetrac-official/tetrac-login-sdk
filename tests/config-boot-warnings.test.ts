// H-2c — boot-time configuration warnings.
//
// `appId` is caller-supplied on EVERY route (body field, `ttc-app-id` header, or ?appId),
// and `config.appId` is only the fallback. With `allowedAppIds` unset — the default —
// validateAppId checks the charset and nothing else, so any well-formed id silently mints
// a working, empty namespace.
//
// That is a DATA-LOSS hazard rather than a tidiness one, because appId is app-key
// derivation input (PBKDF2 salt = SHA-256(appId : email); the wallet app-key message
// embeds `App: {appId}`). A client sending `myapp` at a deployment configured as
// `myapp.example` registers into a different tenant under a different app key, gets a 200,
// and encrypts wallets that the real deployment can never decrypt.
//
// It warns rather than throws: single-app deployments legitimately rely on the fallback
// and never send an appId, so refusing to boot would break them.
import { createAuthHandlers, type ConfigWarning } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";

function boot(config: Record<string, unknown>): ConfigWarning[] {
  const seen: ConfigWarning[] = [];
  createAuthHandlers({
    storage: new MemoryAdapter(),
    config: { origin: "https://test.example", ...config },
    onWarning: (w) => seen.push(w),
  });
  return seen;
}

const codes = (ws: ConfigWarning[]) => ws.map((w) => w.code).sort();

describe("H-2c — unrestricted appId is announced at boot", () => {
  it("🚨 warns when allowedAppIds is unset", () => {
    const ws = boot({ appId: "warn-unset.example" });
    expect(codes(ws)).toContain("unrestricted_app_id");
    // The message must name the failure mode, not just the setting — an integrator who
    // reads "set allowedAppIds" and nothing else has no reason to act on it.
    const w = ws.find((x) => x.code === "unrestricted_app_id")!;
    expect(w.message).toMatch(/never be decrypted|DIFFERENT app key/);
    // ...and it should suggest the value they already have.
    expect(w.message).toContain("warn-unset.example");
  });

  it("stays silent once allowedAppIds is set", () => {
    const ws = boot({ appId: "quiet.example", allowedAppIds: ["quiet.example"] });
    expect(codes(ws)).not.toContain("unrestricted_app_id");
    expect(ws).toHaveLength(0);
  });

  it("an empty allowedAppIds is a deliberate lockout, not 'unset' — still silent", () => {
    // `[]` is falsy-adjacent but NOT falsy; the guard is `!config.allowedAppIds`, so an
    // empty array must keep its meaning (reject everything) rather than re-open the gate.
    const ws = boot({ appId: "empty.example", allowedAppIds: [] });
    expect(codes(ws)).not.toContain("unrestricted_app_id");
  });

  // ONE test may assert `default_app_id`, and this is it.
  //
  // The warning fires only when appId IS the literal default, so its dedupe key is always
  // `default_app_id:ttc` — a second test booting on the default would be deduped and see
  // nothing. So both conditions are asserted from a single fully-default boot, which is
  // also the configuration a first-run integrator actually has.
  it("🚨 a fully default config warns on BOTH counts", () => {
    const ws = boot({});
    expect(codes(ws)).toEqual(["default_app_id", "unrestricted_app_id"]);
    // The server counterpart to AuthClient's default-appId warning, which had no
    // server-side equivalent even though the server is where the namespace is created.
    expect(ws.find((w) => w.code === "default_app_id")!.message).toMatch(/NO cross-app key/);
  });
});

describe("the warning does not become noise", () => {
  it("fires once per process per (code, appId), not once per handler construction", () => {
    // A serverless runtime re-evaluates the module per cold start and a multi-tenant host
    // may build one handler set per app; a warning repeated on every construction is one
    // people filter out.
    const first = boot({ appId: "repeat.example" });
    const second = boot({ appId: "repeat.example" });
    const third = boot({ appId: "repeat.example" });

    expect(codes(first)).toContain("unrestricted_app_id");
    expect(second).toHaveLength(0);
    expect(third).toHaveLength(0);
  });

  it("a DIFFERENT appId on the same host still gets its own warning", () => {
    const a = boot({ appId: "tenant-a.example" });
    const b = boot({ appId: "tenant-b.example" });

    expect(codes(a)).toContain("unrestricted_app_id");
    expect(codes(b)).toContain("unrestricted_app_id");
  });

  it("onWarning replaces console.warn rather than adding to it", () => {
    const spy = jest.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const ws = boot({ appId: "sink.example" });
      expect(codes(ws)).toContain("unrestricted_app_id");
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("falls back to console.warn when no sink is given", () => {
    const spy = jest.spyOn(console, "warn").mockImplementation(() => {});
    try {
      createAuthHandlers({
        storage: new MemoryAdapter(),
        config: { origin: "https://test.example", appId: "console.example" },
      });
      expect(spy).toHaveBeenCalledWith(expect.stringContaining("unrestricted_app_id"));
    } finally {
      spy.mockRestore();
    }
  });
});

describe("the warning describes real behaviour", () => {
  it("🚨 an unlisted appId really is accepted when allowedAppIds is unset", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example", appId: "real.example" },
      onWarning: () => {},
    });

    // A challenge for a namespace the deployment never declared. Reaching the
    // "publicKey or email required" branch means the appId itself passed validation —
    // a rejected appId answers "Invalid appId format" / "Unknown appId" instead.
    const res = await h.challenge(
      new Request("http://localhost/api/auth", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ appId: "not-this-deployment" }),
      }),
    );
    expect(await res.json()).toEqual({ error: "publicKey or email required" });
  });

  it("🚨 and really is rejected once allowedAppIds is set", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        appId: "real2.example",
        allowedAppIds: ["real2.example"],
      },
      onWarning: () => {},
    });

    const res = await h.challenge(
      new Request("http://localhost/api/auth", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ appId: "not-this-deployment" }),
      }),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Unknown appId" });
  });
});
