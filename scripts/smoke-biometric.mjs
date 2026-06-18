#!/usr/bin/env node
// Standalone smoke test for the `unlockViaBiometric` feature — runs against the
// BUILT dist/ (the published artifact), with NO jest, NO browser, NO real
// authenticator. It installs the minimal browser globals the SDK touches
// (IndexedDB v2 multi-store, localStorage/sessionStorage, navigator.credentials
// with a STUBBED PRF/gate secret, window/document), then exercises the real
// HKDF-SHA-256 + AES-256-GCM wrap/unwrap and the enable -> lock -> unlock flow.
//
// Run:  npm run smoke:biometric        (builds dist/ first, then runs this)
//   or: npm run build && node scripts/smoke-biometric.mjs
//
// Exit code 0 = all checks green; 1 = a check failed or dist/ is missing.
// (Mirrors the mocking in tests/biometric-unlock.test.ts so it stays in sync.)

// ---------- tiny assert harness ----------
let failures = 0;
const check = (name, cond) => {
  console.log(`  ${cond ? "✓" : "✗"} ${name}`);
  if (!cond) failures++;
};
const expectThrows = async (name, fn) => {
  try {
    await fn();
    check(`${name}`, false);
  } catch {
    check(`${name}`, true);
  }
};

// ---------- localStorage / sessionStorage shim ----------
const storageShim = () => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => void m.set(k, String(v)),
    removeItem: (k) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    get length() {
      return m.size;
    },
  };
};

// ---------- in-memory IndexedDB shim (shared v2 DB; multi-store; supports delete) ----------
const makeIdbShim = () => {
  const dbs = new Map(); // name -> { version, stores: Map<store, Map<key,value>> }
  const makeDb = (name) => {
    const entry = dbs.get(name);
    return {
      get objectStoreNames() {
        return { contains: (s) => entry.stores.has(s) };
      },
      createObjectStore: (s) => entry.stores.set(s, new Map()),
      transaction(s) {
        const store = entry.stores.get(s);
        const tx = {
          objectStore: () => ({
            put(value, key) {
              store.set(key, value);
              queueMicrotask(() => tx.oncomplete && tx.oncomplete());
            },
            get(key) {
              const req = {};
              queueMicrotask(() => {
                req.result = store.get(key);
                req.onsuccess && req.onsuccess();
              });
              return req;
            },
            delete(key) {
              store.delete(key);
              queueMicrotask(() => tx.oncomplete && tx.oncomplete());
            },
          }),
        };
        return tx;
      },
    };
  };
  return {
    dbs,
    open(name, version) {
      const req = {};
      queueMicrotask(() => {
        const existing = dbs.get(name);
        const oldVersion = existing ? existing.version : 0;
        if (!existing) dbs.set(name, { version, stores: new Map() });
        else if (version > existing.version) existing.version = version;
        req.result = makeDb(name);
        if (version > oldVersion && req.onupgradeneeded) req.onupgradeneeded();
        req.onsuccess && req.onsuccess();
      });
      return req;
    },
  };
};
const idb = makeIdbShim();

// ---------- WebAuthn mock: switchable PRF/gate + decline; deterministic PRF secret ----------
let credMode = "prf"; // "prf" | "gate"
let declineAssertion = false;
let nextPrfHex = "11".repeat(32);
const hexToArrayBuffer = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out.buffer;
};
const randomRawId = () => {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return b.buffer;
};
let pendingRawId = randomRawId();
const makeNavigator = () => ({
  credentials: {
    create: async () => ({
      rawId: pendingRawId,
      getClientExtensionResults: () => (credMode === "prf" ? { prf: { enabled: true } } : {}),
    }),
    get: async () => {
      if (declineAssertion) return null; // user declined / cancelled
      return {
        getClientExtensionResults: () =>
          credMode === "prf" ? { prf: { results: { first: hexToArrayBuffer(nextPrfHex) } } } : {},
      };
    },
  },
});

// ---------- install globals BEFORE importing the built module ----------
const def = (name, value) => Object.defineProperty(globalThis, name, { value, configurable: true });
def("window", globalThis);
def("indexedDB", idb);
def("localStorage", storageShim());
def("sessionStorage", storageShim());
def("navigator", makeNavigator());
def("document", { addEventListener: () => {}, visibilityState: "visible" });

// ---------- import the BUILT artifact ----------
const distUrl = new URL("../dist/client/index.js", import.meta.url);
let mod;
try {
  mod = await import(distUrl.href);
} catch (e) {
  console.error("✗ Could not import dist/client/index.js — run `npm run build` first.\n", e);
  process.exit(1);
}
const {
  configureVault,
  armAppKey,
  lockVault,
  getAppKey,
  enableBiometricUnlock,
  unlockViaBiometric,
  disableBiometricUnlock,
  hasBiometricUnlock,
  AuthClient,
} = mod;

const cfg = { rpId: "localhost", rpName: "TTC smoke", preferPrf: true };
const EMAIL_KEY = "ab".repeat(32); // opaque stand-in app key (email/PBKDF2-shaped, 64 hex)
const WEB3_KEY = "cd".repeat(32); //  opaque stand-in app key (web3/SHA256-shaped, 64 hex)

console.log("\nunlockViaBiometric smoke test — against dist/, real Web Crypto (HKDF + AES-256-GCM)\n");

// 1) PRF mode — wrap/unwrap round-trips the EXACT app key
console.log("PRF mode — round-trip (email-shaped key):");
credMode = "prf";
declineAssertion = false;
nextPrfHex = "11".repeat(32);
pendingRawId = randomRawId();
configureVault({ storageMode: "memory", autoLockMs: 60_000 });
armAppKey(EMAIL_KEY);
const reg1 = await enableBiometricUnlock(cfg, "smoke@prf");
check("hasBiometricUnlock() is true after enable", hasBiometricUnlock() === true);
lockVault();
check("vault is locked after lockVault() (getAppKey null)", getAppKey() === null);
await unlockViaBiometric(reg1);
check("unlockViaBiometric re-arms the EXACT app key", getAppKey() === EMAIL_KEY);

// 2) Tamper fails closed (AES-GCM auth tag)
console.log("\nTamper detection:");
const blobStore = idb.dbs.get("ttc_passkey_store").stores.get("unlock_blobs");
const blob = blobStore.get(reg1.credentialId);
check("a wrapped blob exists in IndexedDB unlock_blobs", !!blob);
new Uint8Array(blob.ciphertext)[0] ^= 0xff; // flip one ciphertext byte in place
lockVault();
await expectThrows("tampered blob -> unlock throws (fails closed)", () => unlockViaBiometric(reg1));
check("vault stays locked after a failed unlock", getAppKey() === null);
await disableBiometricUnlock(reg1);

// 3) Declined biometric fails closed
console.log("\nDeclined assertion:");
credMode = "prf";
nextPrfHex = "22".repeat(32);
pendingRawId = randomRawId();
armAppKey(EMAIL_KEY);
const reg2 = await enableBiometricUnlock(cfg, "smoke@decline");
lockVault();
declineAssertion = true;
await expectThrows("declined/cancelled assertion -> unlock throws", () => unlockViaBiometric(reg2));
declineAssertion = false;
await disableBiometricUnlock(reg2);

// 4) Gate mode — round-trips the EXACT app key (web3-shaped)
console.log("\nGate mode — round-trip (web3-shaped key):");
credMode = "gate";
pendingRawId = randomRawId();
armAppKey(WEB3_KEY);
const reg3 = await enableBiometricUnlock(cfg, "smoke@gate");
lockVault();
await unlockViaBiometric(reg3);
check("gate-mode unlock re-arms the EXACT app key", getAppKey() === WEB3_KEY);

// 5) ReauthCredentials { biometricUnlock } via AuthClient.deriveAppKey (no network)
console.log("\nReauthCredentials { biometricUnlock } via AuthClient.deriveAppKey:");
const client = new AuthClient({ apiBaseUrl: "http://localhost/__none__" });
const derived = await client.deriveAppKey({ biometricUnlock: reg3 });
check("deriveAppKey({ biometricUnlock }) returns the wrapped app key", derived === WEB3_KEY);

// 6) disable purges the blob
console.log("\nDisable purges:");
await disableBiometricUnlock(reg3);
check("hasBiometricUnlock() is false after disable", hasBiometricUnlock() === false);
lockVault();
await expectThrows("unlock after disable throws (no blob)", () => unlockViaBiometric(reg3));

// 7) enable requires an unlocked vault
console.log("\nEnable requires an unlocked vault:");
lockVault();
credMode = "prf";
pendingRawId = randomRawId();
await expectThrows("enable while locked throws (VaultLockedError)", () =>
  enableBiometricUnlock(cfg, "smoke@locked"),
);

console.log("");
if (failures) {
  console.error(`SMOKE FAILED — ${failures} check(s) failed.`);
  process.exit(1);
}
console.log("SMOKE PASSED — all checks green.");
process.exit(0);
