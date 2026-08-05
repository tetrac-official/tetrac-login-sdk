// Biometric / passkey auth via WebAuthn. Browser-only.
//
// PRF ONLY. The authenticator's PRF extension derives a high-entropy secret on every
// assertion; it is never stored, on disk or anywhere else. An authenticator without PRF
// is refused (PrfUnavailableError) rather than downgraded.
//
// There is deliberately no software fallback. The only way to serve a non-PRF device
// would be to mint a random secret and keep it locally — and any such secret must be
// readable by the page in order to be usable, which means readable by any script on the
// origin, with no biometric ceremony involved. That is not a weaker tier of the same
// guarantee; it is the absence of the guarantee. Non-PRF devices use email + passkey or
// a Web3 wallet, both of which re-derive their key from something the user supplies.
import type { WebAuthnConfig } from "../core/config.js";

/**
 * Thrown when the authenticator has no PRF extension. Catch this to steer the user to
 * email + passkey or a Web3 wallet.
 *
 * PRF support cannot be detected before the ceremony — the browser only reports it in
 * the credential's extension results — so attempt-then-catch is the only way to know.
 */
export class PrfUnavailableError extends Error {
  constructor() {
    super(
      "[tetrac] This authenticator does not support the WebAuthn PRF extension, so it " +
        "cannot derive an encryption key without storing one on the device. " +
        "Offer email + passkey or a Web3 wallet instead.",
    );
    this.name = "PrfUnavailableError";
  }
}

export interface PasskeyRegistration {
  credentialId: string; // base64url
  salt: string; // base64url — PRF eval input
  rpId: string;
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

/**
 * Register a new passkey credential with the PRF extension.
 *
 * @throws {PrfUnavailableError} if the authenticator does not report PRF support.
 */
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
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!cred) throw new Error("Passkey registration was cancelled");

  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  if (!ext.prf?.enabled) throw new PrfUnavailableError();

  return {
    credentialId: b64urlEncode(cred.rawId),
    salt: b64urlEncode(salt),
    rpId,
  };
}

/**
 * Unlock and return the passkey-derived secret (hex): the authenticator's PRF output for
 * this credential's salt, released only after a successful `userVerification` assertion.
 * Re-derived every call and never persisted. Use the result as the app/encryption key.
 */
export async function derivePasskeySecret(reg: PasskeyRegistration): Promise<string> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: reg.rpId,
      allowCredentials: [{ type: "public-key", id: b64urlDecode(reg.credentialId) }],
      userVerification: "required",
      timeout: 60_000,
      extensions: {
        prf: { eval: { first: b64urlDecode(reg.salt) } },
      } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) throw new Error("Biometric verification was cancelled");

  const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  const prf = ext.prf?.results?.first;
  if (!prf) throw new PrfUnavailableError();
  return toHex(new Uint8Array(prf));
}

// --- IndexedDB: biometric-unlock wrapped blobs only ---
//
// Nothing secret is stored here. A blob is the account's app key sealed under a key
// HKDF-derived from the PRF secret (see biometricUnlock.ts), and the PRF secret exists
// only for the duration of an assertion. Storage-scraping script reads ciphertext it
// cannot unwrap without a fresh Touch ID.

const DB_NAME = "ttc_passkey_store";
const UNLOCK_STORE = "unlock_blobs";
const DB_VERSION = 2;

/** Open the shared "ttc_passkey_store" IndexedDB, creating the blob store on upgrade. */
export function openPasskeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(UNLOCK_STORE)) db.createObjectStore(UNLOCK_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Name of the object store that holds biometric-unlock wrapped blobs. */
export const UNLOCK_BLOBS_STORE = UNLOCK_STORE;
