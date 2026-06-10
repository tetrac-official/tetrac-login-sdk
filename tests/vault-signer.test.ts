// B2 — Vault-lock bypass. A signer must read getAppKey() at CALL time and throw
// VaultLockedError when the vault has locked (no re-render needed). Runs in the
// node test env (no window/sessionStorage), exercising the in-memory vault +
// lazy auto-lock directly. lockSnapshot() must be a pure, stable read.
import {
  configureVault,
  armAppKey,
  lockVault,
  isLocked,
  getAppKey,
  lockSnapshot,
  VaultLockedError,
} from "../src/client/session";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Mimics what useSigner.sign does: read getAppKey() at call time and refuse to
// operate (throw VaultLockedError) when the vault is locked — never capture the
// key in a closure at construction time.
function makeCallTimeSigner() {
  return {
    sign(): string {
      const key = getAppKey();
      if (key == null) throw new VaultLockedError();
      return `signed-with:${key}`;
    },
  };
}

describe("vault-aware signer (B2)", () => {
  beforeEach(() => {
    lockVault(); // reset module-scope state between tests
  });

  it("arming the vault makes getAppKey() non-null", () => {
    configureVault({ autoLockMs: 10_000, storageMode: "memory" });
    armAppKey("deadbeef");
    expect(getAppKey()).toBe("deadbeef");
    expect(isLocked()).toBe(false);
  });

  it("signs while unlocked, then throws VaultLockedError after lockVault() with no re-render", () => {
    configureVault({ autoLockMs: 10_000, storageMode: "memory" });
    armAppKey("deadbeef");

    // The signer is constructed ONCE while unlocked (simulating a memoized hook).
    const signer = makeCallTimeSigner();
    expect(signer.sign()).toBe("signed-with:deadbeef");

    lockVault();
    expect(getAppKey()).toBeNull();
    // Same signer instance — no re-render — must now refuse.
    expect(() => signer.sign()).toThrow(VaultLockedError);
  });

  it("throws VaultLockedError after auto-lock expiry, again with no re-render", async () => {
    configureVault({ autoLockMs: 40, storageMode: "memory" });
    armAppKey("deadbeef");
    const signer = makeCallTimeSigner();
    expect(signer.sign()).toBe("signed-with:deadbeef");

    await sleep(80); // idle window elapses
    expect(isLocked()).toBe(true);
    expect(() => signer.sign()).toThrow(VaultLockedError);
  });

  it("lockSnapshot() is pure and stable: reflects state without mutating it", () => {
    configureVault({ autoLockMs: 10_000, storageMode: "memory" });

    expect(lockSnapshot()).toBe(false); // locked initially
    armAppKey("deadbeef");
    // Repeated calls return the same value and never lock/unlock as a side effect.
    expect(lockSnapshot()).toBe(true);
    expect(lockSnapshot()).toBe(true);
    expect(getAppKey()).toBe("deadbeef"); // still usable — snapshot didn't disturb it

    lockVault();
    expect(lockSnapshot()).toBe(false);
    expect(lockSnapshot()).toBe(false);
  });

  it("lockSnapshot() reports false once the deadline passes (no rehydrate side effect)", async () => {
    configureVault({ autoLockMs: 40, storageMode: "memory" });
    armAppKey("deadbeef");
    expect(lockSnapshot()).toBe(true);
    await sleep(80);
    expect(lockSnapshot()).toBe(false);
  });
});
