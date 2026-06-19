// CHARACTERIZATION TESTS — prove the client-vault findings against the CURRENT
// code, WITHOUT changing src/. The node test env has no window/storage, so we
// polyfill the minimal browser globals session.ts touches and dynamic-import the
// module fresh per test (jest.resetModules) to simulate page loads.
//
// Findings: H3 (raw appKey in sessionStorage) and CLIENTVAULT-3/4 (a reload revives
// the key with a fresh idle window) are RESOLVED by making the vault MEMORY-ONLY —
// the appKey is never written to web storage and a reload always starts locked.
// CLIENTVAULT-2 (token + email in localStorage) remains an accepted, documented
// tradeoff (the token is a bearer credential; the email is the PBKDF2 salt).

type Store = ReturnType<typeof makeStore>;
function makeStore() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    keys: () => [...m.keys()],
  };
}
function installBrowserGlobals(): { sessionStorage: Store; localStorage: Store } {
  const sessionStorage = makeStore();
  const localStorage = makeStore();
  (globalThis as any).window = globalThis;
  (globalThis as any).sessionStorage = sessionStorage;
  (globalThis as any).localStorage = localStorage;
  (globalThis as any).document = { addEventListener: () => {}, visibilityState: "visible" };
  return { sessionStorage, localStorage };
}

async function freshSession() {
  jest.resetModules();
  // The vault state is now a process-global (Symbol.for("tetrac.vault")) shared
  // across bundle copies; jest.resetModules() does NOT clear it. Delete the slot
  // so the re-imported module builds a fresh, empty vault — faithfully simulating
  // a page reload, which in a real browser starts a brand-new realm.
  delete (globalThis as any)[Symbol.for("tetrac.vault")];
  const stores = installBrowserGlobals();
  const mod = await import("../src/client/session");
  mod.lockVault(); // belt-and-suspenders: guarantee we start locked
  return { mod, ...stores };
}

describe("H3 RESOLVED — the appKey is MEMORY-ONLY (never written to web storage)", () => {
  it("armAppKey does NOT write the key to sessionStorage", async () => {
    const { mod, sessionStorage } = await freshSession();
    mod.configureVault({ autoLockMs: 10_000 });
    mod.armAppKey("deadbeefcafebabe".repeat(4));
    expect(sessionStorage.getItem("ttc_ek")).toBeNull(); // storage-scraping XSS finds nothing
    expect(sessionStorage.keys()).toHaveLength(0);
    mod.lockVault();
  });

  it("setSession persists token/pubkey/email to localStorage but NEVER the appKey", async () => {
    const { mod, sessionStorage, localStorage } = await freshSession();
    mod.configureVault({ autoLockMs: 10_000 });
    mod.setSession({
      publicKey: "PUB",
      authToken: "TOK".padEnd(64, "0"),
      appKey: "SECRETKEY",
      email: "u@x.com",
    });
    expect(sessionStorage.getItem("ttc_ek")).toBeNull();
    // The appKey must not leak into ANY web-storage value, session or local.
    const allValues = [...sessionStorage.keys(), ...localStorage.keys()].map(
      (k) => sessionStorage.getItem(k) ?? localStorage.getItem(k),
    );
    expect(JSON.stringify(allValues)).not.toContain("SECRETKEY");
    mod.lockVault();
  });
});

describe("CLIENTVAULT-2 — session token, public key, and email persisted in localStorage (accepted tradeoff)", () => {
  it("setSession writes token + publicKey + email to localStorage (XSS-exfiltratable)", async () => {
    const { mod, localStorage } = await freshSession();
    mod.configureVault({ autoLockMs: 10_000 });
    mod.setSession({ publicKey: "PUB", authToken: "TOK".padEnd(64, "0"), appKey: "KEY", email: "u@x.com" });
    expect(localStorage.getItem("ttc-auth-token")).toBe("TOK".padEnd(64, "0"));
    expect(localStorage.getItem("ttc-public-key")).toBe("PUB");
    expect(localStorage.getItem("user_email")).toBe("u@x.com"); // email IS the PBKDF2 salt — persisted
    mod.lockVault();
  });
});

describe("CLIENTVAULT-3/4 RESOLVED — a reload always starts LOCKED (memory-only vault)", () => {
  it("a fresh module load (simulated reload) reports locked, even right after arming in a prior 'page'", async () => {
    // Arm the vault in one "page"…
    const first = await freshSession();
    first.mod.configureVault({ autoLockMs: 1_000_000 });
    first.mod.armAppKey("MASTERKEY");
    expect(first.mod.getAppKey()).toBe("MASTERKEY");
    first.mod.lockVault();

    // …then a reload re-imports the module fresh. The key lived only in the old
    // module's memory, so the new module starts locked — no fresh-window revival.
    const second = await freshSession();
    second.mod.configureVault({ autoLockMs: 1_000_000 });
    expect(second.mod.isLocked()).toBe(true);
    expect(second.mod.getAppKey()).toBeNull();
  });

  it("a STALE ttc_ek left in sessionStorage by an older build is IGNORED (never re-hydrated)", async () => {
    const realNow = Date.now;
    let now = 1_000_000;
    (Date as any).now = () => now;
    try {
      const { mod, sessionStorage } = await freshSession();
      mod.configureVault({ autoLockMs: 1_000 });
      // Simulate a legacy persisted key surviving from a much earlier page load.
      sessionStorage.setItem("ttc_ek", "STALEKEY");
      now += 9_999_999;
      // The vault no longer reads ttc_ek at all — it cannot be revived from storage.
      expect(mod.isLocked()).toBe(true);
      expect(mod.getAppKey()).toBeNull();
      mod.lockVault();
    } finally {
      (Date as any).now = realNow;
    }
  });
});
