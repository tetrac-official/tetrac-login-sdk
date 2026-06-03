// Biometric / passkey auth via WebAuthn. Browser-only.
//
// Two modes (matching next-ttc PasskeyService):
//  - PRF (preferred): derive a high-entropy secret from the authenticator's PRF
//    extension. The secret never leaves the Secure Enclave's derivation and is
//    not stored anywhere — it is re-derived on each unlock.
//  - Gate (fallback): when PRF is unavailable, keep a random secret in IndexedDB
//    that can only be read after a successful userVerification assertion.
import type { WebAuthnConfig } from "../core/config.js";

export interface PasskeyRegistration {
  credentialId: string; // base64url
  salt: string; // base64url — PRF eval input
  rpId: string;
  mode: "prf" | "gate";
}

function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Allocate over a concrete ArrayBuffer so the result is a BufferSource
// (WebAuthn options reject the generic Uint8Array<ArrayBufferLike>).
function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
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

const DB_NAME = "ttc_passkey_store";
const STORE = "gate_secrets";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function gateStore(credentialId: string, secret: string): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(secret, credentialId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function gateLoad(credentialId: string): Promise<string | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(credentialId);
    req.onsuccess = () => resolve((req.result as string) ?? null);
    req.onerror = () => reject(req.error);
  });
}
