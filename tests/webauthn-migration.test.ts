// Gate-mode legacy migration: a pre-wrap (v0.1.0) IndexedDB record is a raw
// plaintext hex string. derivePasskeySecret must (1) still unlock that account,
// (2) rewrap the secret under a non-extractable AES-GCM key in place, so the
// readable copy is gone after the first unlock, and (3) keep returning the same
// secret via the wrapped record thereafter.
//
// Runs in the node env with a minimal in-memory IndexedDB shim and a stubbed
// navigator.credentials.get (the assertion result is unused on the gate path).
import { derivePasskeySecret, type PasskeyRegistration } from "../src/client/webauthn";

const subtle = globalThis.crypto?.subtle;
const describeCrypto = subtle ? describe : describe.skip;

// --- minimal IndexedDB shim (just what src/client/webauthn.ts touches) ---

type StoreMap = Map<string, unknown>;

function makeIdbShim() {
  // dbName -> storeName -> key -> value
  const dbs = new Map<string, Map<string, StoreMap>>();

  function makeTx(store: StoreMap) {
    const tx: {
      objectStore: () => {
        put: (value: unknown, key: string) => void;
        get: (key: string) => { onsuccess?: () => void; onerror?: () => void; result?: unknown };
      };
      oncomplete?: () => void;
      onerror?: () => void;
      error?: unknown;
    } = {
      objectStore: () => ({
        put(value: unknown, key: string) {
          store.set(key, value);
          queueMicrotask(() => tx.oncomplete?.());
        },
        get(key: string) {
          const req: { onsuccess?: () => void; onerror?: () => void; result?: unknown } = {};
          queueMicrotask(() => {
            req.result = store.get(key);
            req.onsuccess?.();
          });
          return req;
        },
      }),
    };
    return tx;
  }

  return {
    dbs,
    open(name: string) {
      const req: {
        onupgradeneeded?: () => void;
        onsuccess?: () => void;
        onerror?: () => void;
        result?: unknown;
        error?: unknown;
      } = {};
      queueMicrotask(() => {
        const isNew = !dbs.has(name);
        if (isNew) dbs.set(name, new Map());
        const stores = dbs.get(name)!;
        req.result = {
          createObjectStore: (s: string) => void stores.set(s, new Map()),
          transaction: (s: string) => makeTx(stores.get(s)!),
        };
        if (isNew) req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };
}

const idb = makeIdbShim();

beforeAll(() => {
  Object.defineProperty(globalThis, "indexedDB", { value: idb, configurable: true });
  // Gate-path assertion: only "non-null with extension results" matters.
  Object.defineProperty(globalThis, "navigator", {
    value: {
      credentials: {
        get: async () => ({ getClientExtensionResults: () => ({}) }),
      },
    },
    configurable: true,
  });
});

describeCrypto("gate-mode legacy record migration (B3 follow-up)", () => {
  const DB = "ttc_passkey_store";
  const STORE = "gate_secrets";
  const credentialId = "AAAA"; // valid base64url for the allowCredentials decode
  const legacySecret = "ab".repeat(32); // 32-byte hex, as the old gateStore wrote it

  const reg: PasskeyRegistration = {
    credentialId,
    salt: "AAAA",
    rpId: "localhost",
    mode: "gate",
  };

  function gateStoreMap(): StoreMap {
    return idb.dbs.get(DB)!.get(STORE)!;
  }

  beforeAll(() => {
    // Seed a legacy plaintext record exactly as SDK v0.1.0 stored it.
    idb.dbs.set(DB, new Map([[STORE, new Map<string, unknown>([[credentialId, legacySecret]])]]));
  });

  it("unlocks a legacy plaintext record and rewraps it in place", async () => {
    expect(typeof gateStoreMap().get(credentialId)).toBe("string"); // legacy on disk

    const secret = await derivePasskeySecret(reg);
    expect(secret).toBe(legacySecret); // the account still unlocks

    // The record is no longer a readable string — it's the wrapped shape.
    const record = gateStoreMap().get(credentialId) as {
      cryptoKey: CryptoKey;
      iv: Uint8Array;
      ciphertext: ArrayBuffer;
    };
    expect(typeof record).toBe("object");
    expect(record.cryptoKey).toBeDefined();
    expect(record.cryptoKey.extractable).toBe(false);
    expect(record.iv).toBeInstanceOf(Uint8Array);
    // The ciphertext must not be (or contain) the plaintext hex.
    expect(record.ciphertext).not.toBe(legacySecret);
  });

  it("subsequent unlocks decrypt the wrapped record to the same secret", async () => {
    const again = await derivePasskeySecret(reg);
    expect(again).toBe(legacySecret);
    // Still wrapped — the migration is one-way.
    expect(typeof gateStoreMap().get(credentialId)).toBe("object");
  });
});
