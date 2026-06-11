// CHARACTERIZATION TESTS — prove the client-vault findings against the CURRENT
// code, WITHOUT changing src/. The node test env has no window/storage, so we
// polyfill the minimal browser globals session.ts touches and dynamic-import the
// module fresh per test (jest.resetModules) to simulate page loads.
//
// Findings: H3 (raw appKey in sessionStorage by default), CLIENTVAULT-2 (token +
// email in localStorage), CLIENTVAULT-3 (auto-lock deadline reset on reload).
import { DEFAULT_CONFIG } from "../src/core/config";

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
  const stores = installBrowserGlobals();
  const mod = await import("../src/client/session");
  mod.lockVault(); // reset any module-scope state that survived (memory key/timer)
  return { mod, ...stores };
}

describe("H3 — default appKeyStorage 'session' persists the raw appKey to sessionStorage (XSS-readable)", () => {
  it("DEFAULT_CONFIG.appKeyStorage is 'session' (the at-risk default)", () => {
    expect(DEFAULT_CONFIG.appKeyStorage).toBe("session");
  });

  it("arming the vault writes the cleartext master key under 'ttc_ek'", async () => {
    const { mod, sessionStorage } = await freshSession();
    mod.configureVault({ storageMode: "session", autoLockMs: 10_000 });
    const appKey = "deadbeefcafebabe".repeat(4); // the key that decrypts EVERY wallet
    mod.armAppKey(appKey);
    // Any same-origin script (XSS / malicious dependency / extension) reads it synchronously:
    expect(sessionStorage.getItem("ttc_ek")).toBe(appKey);
    mod.lockVault();
  });
});

describe("CLIENTVAULT-2 — session token, public key, and email persisted in localStorage", () => {
  it("setSession writes token + publicKey + email to localStorage (XSS-exfiltratable)", async () => {
    const { mod, localStorage } = await freshSession();
    mod.configureVault({ storageMode: "session", autoLockMs: 10_000 });
    mod.setSession({ publicKey: "PUB", authToken: "TOK".padEnd(64, "0"), appKey: "KEY", email: "u@x.com" });
    expect(localStorage.getItem("ttc-auth-token")).toBe("TOK".padEnd(64, "0"));
    expect(localStorage.getItem("ttc-public-key")).toBe("PUB");
    expect(localStorage.getItem("user_email")).toBe("u@x.com"); // email IS the PBKDF2 salt — now persisted
    mod.lockVault();
  });
});

describe("CLIENTVAULT-3 — auto-lock deadline is never persisted; a reload resets the idle window", () => {
  it("only the key (no expiry) is stored, so the idle clock cannot survive a reload", async () => {
    const { mod, sessionStorage } = await freshSession();
    mod.configureVault({ storageMode: "session", autoLockMs: 15_000 });
    mod.armAppKey("KEY");
    const keys = sessionStorage.keys();
    expect(keys).toContain("ttc_ek");
    expect(keys.some((k) => /exp|deadline|lock/i.test(k))).toBe(false); // no persisted deadline
    mod.lockVault();
  });

  it("a reloaded tab re-hydrates UNLOCKED with a FRESH window, ignoring how long the key sat idle", async () => {
    const realNow = Date.now;
    let now = 1_000_000;
    (Date as any).now = () => now;
    try {
      const { mod, sessionStorage } = await freshSession();
      mod.configureVault({ storageMode: "session", autoLockMs: 1_000 });
      // Simulate the key having survived in sessionStorage from a much earlier page load:
      sessionStorage.setItem("ttc_ek", "MASTERKEY");
      now += 9_999_999; // ~hours later — far past the 1s idle window

      // The lazy re-hydrate path hands the key back and arms a brand-new deadline:
      expect(mod.isLocked()).toBe(false);
      expect(mod.getAppKey()).toBe("MASTERKEY");

      // Confirm the deadline was RESET (not carried over): still unlocked just under the fresh window,
      now += 500;
      expect(mod.getAppKey()).toBe("MASTERKEY");
      // …and only locks after the FRESH autoLockMs elapses.
      now += 1_000;
      expect(mod.getAppKey()).toBeNull();
      mod.lockVault();
    } finally {
      (Date as any).now = realNow;
    }
  });
});
