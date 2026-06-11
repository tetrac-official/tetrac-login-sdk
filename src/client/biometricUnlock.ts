// Optional biometric UNLOCK for ANY account (email / web3 / biometric-primary).
// Browser-only. See features/unlockViaBiometric.md (docs/unlockViaBiometric.md).
//
// CORE IDEA — wrap the app key, never replace it:
//   The passkey secret here does NOT become the app key (that is the separate
//   biometric-PRIMARY flow, `{ registration }`). Instead it WRAPS the account's
//   existing app key: on enable we AES-GCM-encrypt the current app key under a
//   key derived from a freshly-registered passkey secret; on unlock a biometric
//   assertion re-derives that secret, decrypts the blob, and re-arms the vault.
//   Because we recover the account's OWN app key, every downstream path (wallet
//   decrypt / sign / reveal) works unchanged for any auth method.
//
// AT-REST SAFETY: the wrapped blob can sit in IndexedDB because unwrapping always
// requires a fresh Touch ID assertion — the PRF secret is never persisted, and
// the gate secret is held under a non-extractable AES-GCM key released only after
// a successful userVerification assertion. Storage-scraping XSS reads ciphertext
// it can never unwrap.
//
// CRYPTO (PRD §4): NEW data, no byte-compat constraint, so this uses NATIVE
// WebCrypto authenticated encryption (AES-256-GCM) — NOT the compat-locked
// crypto-es AES-CBC used for wallets. The AES key is HKDF-SHA-256 of the passkey
// secret (the raw PRF/gate secret is NEVER used directly as a key).
import type { WebAuthnConfig } from "../core/config.js";
import { armAppKey, getAppKey, VaultLockedError, registerSessionClearHook } from "./session.js";
import {
  registerPasskey,
  derivePasskeySecret,
  gateDelete,
  b64urlDecode,
  openPasskeyDb,
  UNLOCK_BLOBS_STORE,
  type PasskeyRegistration,
} from "./webauthn.js";

// --- constants ---

// Marker in localStorage so hasBiometricUnlock() can answer SYNC (IndexedDB is
// async). The marker is NON-SENSITIVE — it holds only the credentialId; the
// wrapped blob (the only secret-bearing artifact) stays in IndexedDB.
const MARKER_KEY = "ttc_biometric_unlock";
// HKDF info string — domain-separates this key derivation; versioned for rotation.
const HKDF_INFO = "ttc-biometric-unlock-v1";

const hasWindow = (): boolean => typeof window !== "undefined";

/** Versioned wrapped-key blob shape stored in IndexedDB, keyed by credentialId. */
interface UnlockBlob {
  v: 1;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

// --- HKDF + AES-GCM wrap / unwrap ---

/**
 * Derive the AES-256-GCM wrapping key from the passkey secret via HKDF-SHA-256:
 *   salt = the credentialId BYTES (b64url-decoded), info = "ttc-biometric-unlock-v1".
 * The raw PRF/gate secret is never used directly as the AES key.
 */
async function deriveWrapKey(credentialId: string, secretHex: string): Promise<CryptoKey> {
  const ikm = fromHex(secretHex);
  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: b64urlDecode(credentialId),
      info: new TextEncoder().encode(HKDF_INFO),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable: the wrap key never leaves crypto.subtle
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt the app key (UTF-8 string) under HKDF(secret) with AES-256-GCM and a
 * random 12-byte IV, then persist the { v, iv, ciphertext } blob in IndexedDB
 * keyed by credentialId. Authenticated (AEAD) — tamper-evident by construction.
 */
async function wrapAppKey(credentialId: string, secretHex: string, appKey: string): Promise<void> {
  const key = await deriveWrapKey(credentialId, secretHex);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(appKey),
  );
  const blob: UnlockBlob = { v: 1, iv, ciphertext };
  await blobPut(credentialId, blob);
}

/**
 * Load the blob for a credential, re-derive the same HKDF key, and AES-GCM-decrypt
 * to recover the app key. Throws (fails closed) on tamper, a wrong/declined
 * secret, or a missing blob — there is no fallback path.
 *
 * Exported so AuthClient.deriveAppKey can resolve the `{ biometricUnlock }`
 * re-auth variant: derivePasskeySecret(reg) -> unwrapAppKey(reg.credentialId, secret).
 */
export async function unwrapAppKey(credentialId: string, secretHex: string): Promise<string> {
  const blob = await blobGet(credentialId);
  if (!blob) throw new Error("No biometric-unlock blob registered for this credential");
  const key = await deriveWrapKey(credentialId, secretHex);
  // AES-GCM verifies the auth tag before returning — a tampered blob or a wrong
  // secret throws here, so we fail closed.
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.iv }, key, blob.ciphertext);
  return new TextDecoder().decode(plain);
}

// --- IndexedDB "unlock_blobs" store (in the shared ttc_passkey_store DB) ---

async function blobPut(credentialId: string, blob: UnlockBlob): Promise<void> {
  const db = await openPasskeyDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UNLOCK_BLOBS_STORE, "readwrite");
    tx.objectStore(UNLOCK_BLOBS_STORE).put(blob, credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function blobGet(credentialId: string): Promise<UnlockBlob | null> {
  const db = await openPasskeyDb();
  return new Promise<UnlockBlob | null>((resolve, reject) => {
    const tx = db.transaction(UNLOCK_BLOBS_STORE, "readonly");
    const req = tx.objectStore(UNLOCK_BLOBS_STORE).get(credentialId);
    req.onsuccess = () => resolve((req.result as UnlockBlob | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function blobDelete(credentialId: string): Promise<void> {
  const db = await openPasskeyDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(UNLOCK_BLOBS_STORE, "readwrite");
    tx.objectStore(UNLOCK_BLOBS_STORE).delete(credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// --- hex helpers (match webauthn.ts) ---

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(new ArrayBuffer(n));
  crypto.getRandomValues(b);
  return b;
}

// --- public API (PRD §3.1) ---

/** True if a biometric-unlock blob is registered on THIS device. Sync. */
export function hasBiometricUnlock(): boolean {
  if (!hasWindow()) return false;
  return localStorage.getItem(MARKER_KEY) !== null;
}

/**
 * Wrap the CURRENT vault app key under a freshly-registered passkey secret and
 * persist it. The vault MUST be unlocked (throws VaultLockedError otherwise —
 * you can only wrap a key you currently hold). Returns the PasskeyRegistration
 * the app must persist to call unlockViaBiometric / disableBiometricUnlock later.
 */
export async function enableBiometricUnlock(
  config: WebAuthnConfig,
  userName: string,
): Promise<PasskeyRegistration> {
  const appKey = getAppKey();
  if (appKey === null) throw new VaultLockedError();

  const registration = await registerPasskey(config, userName); // Touch ID (create)
  const secret = await derivePasskeySecret(registration); // Touch ID (get) -> hex secret
  await wrapAppKey(registration.credentialId, secret, appKey);

  // Sync marker so hasBiometricUnlock() works without touching IndexedDB.
  if (hasWindow()) localStorage.setItem(MARKER_KEY, registration.credentialId);
  return registration;
}

/**
 * Touch ID -> derive the passkey secret -> unwrap the stored app key -> armAppKey().
 * Re-arms the vault for ANY account (restarts the auto-lock window). Throws if no
 * blob/registration exists, the blob is tampered, or the assertion is declined.
 */
export async function unlockViaBiometric(registration: PasskeyRegistration): Promise<void> {
  const secret = await derivePasskeySecret(registration); // Touch ID
  const appKey = await unwrapAppKey(registration.credentialId, secret);
  armAppKey(appKey);
}

/**
 * Remove the wrapped blob + the gate secret + the on-device marker for a
 * credential. After this, hasBiometricUnlock() is false and the at-rest blob is
 * gone. Idempotent.
 */
export async function disableBiometricUnlock(registration: PasskeyRegistration): Promise<void> {
  await purge(registration.credentialId);
}

// --- logout purge wiring (no session -> biometricUnlock import cycle) ---

/**
 * Purge all biometric-unlock state for a credential: the IndexedDB wrapped blob,
 * the gate secret (gate mode only; no-op for PRF), and the sync localStorage
 * marker. Always removes the marker first so a half-completed purge can't leave
 * hasBiometricUnlock() reporting true.
 */
async function purge(credentialId: string): Promise<void> {
  if (hasWindow()) localStorage.removeItem(MARKER_KEY);
  await blobDelete(credentialId);
  await gateDelete(credentialId);
}

// On logout (clearSession), purge the registered credential's blob + gate secret.
// We read the credentialId from the SYNC marker (the registration object isn't
// available here) and fire the async purge best-effort. Registered at module
// load; session.ts never imports this file, so there is no import cycle.
registerSessionClearHook(() => {
  if (!hasWindow()) return;
  const credentialId = localStorage.getItem(MARKER_KEY);
  // Remove the marker synchronously so hasBiometricUnlock() flips immediately,
  // then clear the durable stores asynchronously (best-effort).
  localStorage.removeItem(MARKER_KEY);
  if (!credentialId) return;
  void blobDelete(credentialId).catch(() => {});
  void gateDelete(credentialId).catch(() => {});
});
