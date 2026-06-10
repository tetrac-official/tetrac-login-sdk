// Vault lock-model tests (docs/PRD_HOTFIX.md). Runs in the node test env, where
// there is no window/sessionStorage — the in-memory app key + lazy auto-lock are
// exercised directly.
import {
  configureVault,
  armAppKey,
  touchVault,
  lockVault,
  isLocked,
  getAppKey,
  VaultLockedError,
} from "../src/client/session";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("vault lock model", () => {
  beforeEach(() => {
    lockVault(); // reset module-scope state between tests
  });

  it("arms an app key and reports unlocked", () => {
    configureVault({ autoLockMs: 10_000, storageMode: "memory" });
    armAppKey("deadbeef");
    expect(isLocked()).toBe(false);
    expect(getAppKey()).toBe("deadbeef");
  });

  it("lockVault() drops the key immediately", () => {
    configureVault({ autoLockMs: 10_000, storageMode: "memory" });
    armAppKey("deadbeef");
    lockVault();
    expect(isLocked()).toBe(true);
    expect(getAppKey()).toBeNull();
  });

  it("auto-locks after the idle window elapses", async () => {
    configureVault({ autoLockMs: 40, storageMode: "memory" });
    armAppKey("deadbeef");
    expect(getAppKey()).toBe("deadbeef");
    await sleep(80);
    expect(isLocked()).toBe(true);
    expect(getAppKey()).toBeNull();
  });

  it("touchVault() extends the unlocked window", async () => {
    configureVault({ autoLockMs: 120, storageMode: "memory" });
    armAppKey("deadbeef");
    await sleep(80);
    touchVault(); // reset the deadline before it would have expired
    await sleep(80); // 160ms total since arm, but only 80ms since touch
    expect(getAppKey()).toBe("deadbeef");
  });

  it("VaultLockedError is a named Error", () => {
    const e = new VaultLockedError();
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("VaultLockedError");
  });

  // M6 — lockOnHide must be toggleable after the first bind. In the node env there
  // is no `document`, so the visibilitychange handler is never bound; we just assert
  // configureVault accepts the flag (both ways) and never throws, and that arm/lock
  // behavior is unaffected by the flag value.
  it("configureVault accepts lockOnHide both ways without affecting arm/lock", () => {
    expect(() => configureVault({ lockOnHide: false, autoLockMs: 10_000, storageMode: "memory" })).not.toThrow();
    armAppKey("deadbeef");
    expect(getAppKey()).toBe("deadbeef"); // arm still works with hide-locking disabled

    expect(() => configureVault({ lockOnHide: true })).not.toThrow();
    expect(getAppKey()).toBe("deadbeef"); // toggling the flag doesn't disturb the key
    lockVault();
    expect(getAppKey()).toBeNull(); // explicit lock still works
  });
});
