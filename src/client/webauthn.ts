// Biometric / passkey auth via WebAuthn. Browser-only.
//
// Two modes (matching next-ttc PasskeyService):
//  - PRF (preferred): derive a high-entropy secret from the authenticator's PRF
//    extension. The secret never leaves the Secure Enclave's derivation and is
//    not stored anywhere — it is re-derived on each unlock.
//  - Gate (fallback): when PRF is unavailable, keep a random secret that can
//    only be read after a successful userVerification assertion. The secret is
//    never persisted readably: it is wrapped under a NON-EXTRACTABLE AES-GCM
//    CryptoKey (PRD §3) which IndexedDB structured-clones, so any script on the
//    origin sees only the opaque key handle + IV + ciphertext, never the plaintext.
import type { WebAuthnConfig } from "../core/config.js";

export interface PasskeyRegistration {
  credentialId: string; // base64url
  salt: string; // base64url — PRF eval input
  rpId: string;
  mode: "prf" | "gate";
}

export function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Allocate over a concrete ArrayBuffer so the result is a BufferSource
// (WebAuthn options reject the generic Uint8Array<ArrayBufferLike>).
export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(new ArrayBuffer(n));
  crypto.getRandomValues(b);
  return b;
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** True if the platform exposes WebAuthn + a platform (biometric) authenticator. */
export async function isBiometricAvailable(): Promise<boolean> {
  if (typeof window === "undefined" || !window.PublicKeyCredential) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

function rpIdOf(config: WebAuthnConfig): string {
  return config.rpId ?? (typeof window !== "undefined" ? window.location.hostname : "localhost");
}

/** Register a new passkey credential, requesting the PRF extension. */
export async function registerPasskey(
  config: WebAuthnConfig,
  userName: string,
): Promise<PasskeyRegistration> {
  const rpId = rpIdOf(config);
  const salt = randomBytes(32);
  const userId = randomBytes(16);

  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { id: rpId, name: config.rpName },
      user: { id: userId, name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "preferred",
      },
      timeout: 60_000,
      extensions: config.preferPrf ? ({ prf: {} } as AuthenticationExtensionsClientInputs) : undefined,
    },
  })) as PublicKeyCredential | null;

  if (!cred) throw new Error("Passkey registration was cancelled");

  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  const mode: "prf" | "gate" = config.preferPrf && ext.prf?.enabled ? "prf" : "gate";

  const reg: PasskeyRegistration = {
    credentialId: b64urlEncode(cred.rawId),
    salt: b64urlEncode(salt),
    rpId,
    mode,
  };

  // Gate mode needs a stored secret unlocked by future assertions.
  if (mode === "gate") {
    await gateStore(reg.credentialId, toHex(randomBytes(32)));
  }
  return reg;
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Unlock and return the passkey-derived secret (hex). For PRF mode this is the
 * PRF output; for gate mode it is the stored secret, returned only after a
 * successful biometric assertion. Use the result as the app/encryption key.
 */
export async function derivePasskeySecret(reg: PasskeyRegistration): Promise<string> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: reg.rpId,
      allowCredentials: [{ type: "public-key", id: b64urlDecode(reg.credentialId) }],
      userVerification: "required",
      timeout: 60_000,
      extensions:
        reg.mode === "prf"
          ? ({ prf: { eval: { first: b64urlDecode(reg.salt) } } } as AuthenticationExtensionsClientInputs)
          : undefined,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Biometric verification was cancelled");

  if (reg.mode === "prf") {
    const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
    const prf = ext.prf?.results?.first;
    if (!prf) throw new Error("PRF result missing; authenticator may not support PRF");
    return toHex(new Uint8Array(prf));
  }

  // Gate mode: assertion succeeded (biometric verified) -> release stored secret.
  const secret = await gateLoad(reg.credentialId);
  if (!secret) throw new Error("Gate secret not found for this credential");
  return secret;
}

// --- Minimal IndexedDB store for gate-mode secrets ---
//
// The stored record is { cryptoKey, iv, ciphertext }: the cryptoKey is a
// non-extractable AES-GCM key (structured-cloned by IndexedDB — its bytes are
// never exposed to JS), and the hex secret is held only as AES-GCM ciphertext.
// Reading the record back yields nothing usable without crypto.subtle.decrypt,
// which can only run via the in-memory non-extractable key handle.

const DB_NAME = "ttc_passkey_store";
const STORE = "gate_secrets";
// Biometric-unlock wrapped-key blobs live in the SAME database (see
// biometricUnlock.ts). Both stores are created by the shared opener below at
// DB version 2, so the two modules never race to open the DB at different
// versions (a mismatch would throw IndexedDB VersionError on the lower open).
const UNLOCK_STORE = "unlock_blobs";
const DB_VERSION = 2;

interface GateRecord {
  cryptoKey: CryptoKey;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

/**
 * Open the shared "ttc_passkey_store" IndexedDB at the current version, creating
 * BOTH object stores ("gate_secrets" + "unlock_blobs") on upgrade. Exported so
 * biometricUnlock.ts reuses the exact same opener — there must be exactly one
 * source of truth for the DB version and its schema.
 */
export function openPasskeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // Create each store only if absent — handles both fresh installs and the
      // v1 -> v2 upgrade (where gate_secrets already exists).
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      if (!db.objectStoreNames.contains(UNLOCK_STORE)) db.createObjectStore(UNLOCK_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** @deprecated internal alias retained for the gate helpers below. */
const openDb = openPasskeyDb;

// Wrap: generate a non-extractable AES-GCM key, encrypt the hex secret under it
// with a random 12-byte IV, and persist only the opaque key + IV + ciphertext.
async function gateStore(credentialId: string, secret: string): Promise<void> {
  const cryptoKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable: raw key bytes can never be read back out
    ["encrypt", "decrypt"],
  );
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, fromHex(secret));
  const record: GateRecord = { cryptoKey, iv, ciphertext };

  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(record, credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Unwrap: load the record and decrypt the ciphertext with the non-extractable
// key handle to recover the hex secret. Returns null if no record exists.
async function gateLoad(credentialId: string): Promise<string | null> {
  const db = await openDb();
  const record = await new Promise<GateRecord | string | undefined>((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(credentialId);
    req.onsuccess = () => resolve(req.result as GateRecord | string | undefined);
    req.onerror = () => reject(req.error);
  });
  if (!record) return null;

  // Legacy record (pre-wrap format): the secret was stored as a plaintext hex
  // string. Use it this once and rewrap it under a fresh non-extractable key —
  // gateStore overwrites the record, so the readable copy is gone after this.
  if (typeof record === "string") {
    await gateStore(credentialId, record);
    return record;
  }

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: record.iv },
    record.cryptoKey,
    record.ciphertext,
  );
  return toHex(new Uint8Array(plain));
}

/**
 * Delete the gate secret for a credential. Used by disableBiometricUnlock /
 * logout purge so a removed credential leaves no recoverable secret behind.
 * No-op for PRF credentials (which never stored a gate secret).
 */
export async function gateDelete(credentialId: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Name of the object store that holds biometric-unlock wrapped blobs. */
export const UNLOCK_BLOBS_STORE = UNLOCK_STORE;
