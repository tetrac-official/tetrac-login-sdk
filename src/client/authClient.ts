// High-level browser auth client. Orchestrates key derivation, client-side wallet
// generation, the API round-trips, and session storage for all three methods.
import { resolveConfig, PBKDF2_ITERATIONS, type AuthConfig, type DeepPartial } from "../core/config.js";
import { deriveAppKeyFromPasskey, deriveAppKeyFromSignature } from "../core/crypto.js";
import { deriveAuthPublicKey, signAuthChallenge } from "./authKey.js";
import { walletLoginMessage, walletAppKeyMessage } from "../core/index.js";
import type { AuthResult, EncryptedWallet, UserData, WalletRole } from "../core/types.js";
import { generateWalletBundle, flattenBundle, decryptWalletSecret } from "./wallet.js";
import {
  setSession,
  clearSession,
  authHeaders,
  armAppKey,
  getAuthToken,
  getEmail,
  getPbkdf2Iterations,
  configureVault,
} from "./session.js";
import { registerPasskey, derivePasskeySecret, type PasskeyRegistration } from "./webauthn.js";
import {
  enableBiometricUnlock,
  unlockViaBiometric,
  disableBiometricUnlock,
  hasBiometricUnlock,
  unwrapAppKey,
} from "./biometricUnlock.js";

/**
 * Credentials for a re-authentication ceremony (unlock or reveal). Exactly one
 * shape is supplied, matching the account's auth method:
 *  - email:     { passkey }         (email is read from the session)
 *  - wallet:    { signMessage }     (re-signs the fixed app-key message)
 *  - biometric: { registration }    (biometric-PRIMARY; the derived secret IS the app key)
 *  - any:       { biometricUnlock } (the derived secret UNWRAPS a stored app key)
 *
 * IMPORTANT DISTINCTION (do not confuse — this is the bug this feature prevents):
 *  - `{ registration }`    = biometric-PRIMARY account. derivePasskeySecret(reg)
 *    IS the app key (registerWithBiometric made it so). Valid ONLY for accounts
 *    created with registerWithBiometric.
 *  - `{ biometricUnlock }` = OPTIONAL unlock layer on ANY account. The derived
 *    secret does NOT equal the app key — it HKDF-derives an AES key that UNWRAPS
 *    a previously-stored blob of the account's real app key.
 *  They are NOT interchangeable: feeding `{ registration }` for an email/web3
 *  account derives the wrong key and locks the user out — use `{ biometricUnlock }`.
 */
export type ReauthCredentials =
  | { passkey: string }
  | { signMessage: (message: Uint8Array) => Promise<Uint8Array> }
  | { registration: PasskeyRegistration }
  | { biometricUnlock: PasskeyRegistration };

export interface WalletGenConfig {
  solana?: WalletRole[];
  evm?: WalletRole[];
}

export interface AuthClientOptions {
  /** Base URL of the auth API, e.g. "/api/auth". */
  apiBaseUrl: string;
  config?: DeepPartial<AuthConfig>;
  /** Which wallets to generate at sign-up. Defaults to funds+signing on both chains. */
  walletGen?: WalletGenConfig;
}

const DEFAULT_WALLET_GEN: WalletGenConfig = {
  solana: ["funds", "signing"],
  evm: ["funds", "signing"],
};

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Stable internal identifier for a biometric account, derived from its credential. */
function biometricEmail(reg: PasskeyRegistration): string {
  return `bio_${reg.credentialId}@passkey.local`;
}

export class AuthClient {
  private readonly config: AuthConfig;
  private readonly walletGen: WalletGenConfig;

  constructor(private readonly opts: AuthClientOptions) {
    this.config = resolveConfig(opts.config);
    this.walletGen = opts.walletGen ?? DEFAULT_WALLET_GEN;
    // Apply the auto-lock policy to the vault (idempotent). The app key is
    // memory-only; there is no storage mode to configure.
    configureVault({
      autoLockMs: this.config.autoLockMs,
      lockOnHide: this.config.lockOnHide,
    });
    // appId domain-separates every app key. Left at the default it provides NO
    // cross-app isolation — nudge integrators to set a unique, stable value.
    if (this.config.appId === "ttc") {
      // eslint-disable-next-line no-console
      console.warn(
        "[tetrac] config.appId is the default 'ttc' — set a unique, stable appId per deployment " +
          "for cross-app key isolation (changing it later re-derives all app keys).",
      );
    }
  }

  // --- Re-authentication (unlock + reveal) ---

  /**
   * Re-derive the app key from a fresh ceremony — WITHOUT mutating the session.
   * Used by both unlock() (which then arms it) and revealSecret() (which uses it
   * once and discards it).
   */
  async deriveAppKey(creds: ReauthCredentials): Promise<string> {
    if ("passkey" in creds) {
      const email = getEmail();
      if (!email) throw new Error("No email in session for passkey re-auth");
      // Use the iteration count pinned for this account at registration (legacy: 100k fallback).
      const iterations = getPbkdf2Iterations() ?? 100_000;
      return deriveAppKeyFromPasskey(creds.passkey, email, iterations, this.config.appId);
    }
    if ("signMessage" in creds) {
      const sig = await creds.signMessage(new TextEncoder().encode(walletAppKeyMessage(this.config.appId)));
      return deriveAppKeyFromSignature(bytesToHex(sig));
    }
    if ("registration" in creds) {
      // Biometric-PRIMARY: the passkey secret IS the app key.
      return derivePasskeySecret(creds.registration);
    }
    if ("biometricUnlock" in creds) {
      // Optional unlock layer (ANY account): the secret UNWRAPS the stored app key.
      // A fresh assertion runs every call, so revealSecret keeps its "re-auth to
      // reveal" guarantee and unlock() restarts the auto-lock window as usual.
      const secret = await derivePasskeySecret(creds.biometricUnlock);
      return unwrapAppKey(creds.biometricUnlock.credentialId, secret);
    }
    throw new Error("Invalid re-auth credentials");
  }

  /**
   * Unlock the vault: re-run the ceremony, optionally validate by decrypting a
   * known wallet, then arm the app key (restarting the auto-lock window). This is
   * how an app re-enables signing after an auto-lock.
   */
  async unlock(creds: ReauthCredentials, validateWith?: EncryptedWallet): Promise<void> {
    const appKey = await this.deriveAppKey(creds);
    if (validateWith) {
      try {
        await decryptWalletSecret(validateWith, appKey);
      } catch {
        throw new Error("Re-authentication failed — wrong credentials");
      }
    }
    armAppKey(appKey);
  }

  /**
   * Reveal a single wallet's plaintext secret behind a fresh ceremony. Derives a
   * one-time key, decrypts, and returns the plaintext — it does NOT arm the
   * session, so a reveal never silently extends the signing window. This is the
   * "Re-auth to reveal" guarantee (PRD §10).
   */
  async revealSecret(wallet: EncryptedWallet, creds: ReauthCredentials): Promise<string> {
    const appKey = await this.deriveAppKey(creds);
    try {
      return await decryptWalletSecret(wallet, appKey);
    } catch {
      throw new Error("Re-authentication failed — wrong credentials");
    }
  }

  private async post<T>(path: string, body: unknown, withAuth = false): Promise<T> {
    const res = await fetch(`${this.opts.apiBaseUrl}/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(withAuth ? this.authHeaders() : {}) },
      // appId rides in the body of every auth-flow call so the server scopes this
      // app's records within a shared Redis/Upstash DB (multi-app, v0.4.0).
      body: JSON.stringify({ appId: this.config.appId, ...(body as Record<string, unknown>) }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as { error?: string }).error ?? `Request failed (${res.status})`);
    return data as T;
  }

  /** Session + public-key + appId headers for authenticated requests. */
  private authHeaders(): Record<string, string> {
    return { ...authHeaders(), [this.config.appIdHeader]: this.config.appId };
  }

  /** Fetch the authenticated user's full record (identity + encrypted wallets). */
  async fetchUserData(): Promise<UserData | null> {
    const res = await fetch(`${this.opts.apiBaseUrl}/user-data`, { headers: this.authHeaders() });
    if (res.status === 401) return null;
    if (!res.ok) throw new Error(`user-data failed (${res.status})`);
    const data = (await res.json().catch(() => ({}))) as { user?: UserData };
    return data.user ?? null;
  }

  // --- Email + passkey ---

  /** Register an email/passkey account; generates and encrypts wallets client-side. */
  async registerWithEmail(params: { email: string; passkey: string }): Promise<AuthResult> {
    const iterations = PBKDF2_ITERATIONS[this.config.securityLevel];
    const appKey = deriveAppKeyFromPasskey(params.passkey, params.email, iterations, this.config.appId);
    const bundle = await generateWalletBundle({ appKey, ...this.walletGen });
    const identity =
      bundle.solana?.funds ?? Object.values(bundle.solana ?? {})[0] ?? Object.values(bundle.evm ?? {})[0];
    if (!identity) throw new Error("walletGen must produce at least one wallet");

    const result = await this.post<AuthResult>("register", {
      publicKey: identity.publicKey,
      email: params.email,
      authPublicKey: deriveAuthPublicKey(appKey),
      authMethod: "email",
      wallets: flattenBundle(bundle),
      pbkdf2Iterations: iterations, // pin the count per-user so future level changes don't orphan this account
    });
    setSession({
      publicKey: result.publicKey,
      authToken: result.authToken,
      appKey,
      email: params.email,
      pbkdf2Iterations: iterations,
    });
    return result;
  }

  /** Log in with email + passkey. Re-derives the app key to unlock wallets. */
  async loginWithEmail(params: { email: string; passkey: string }): Promise<AuthResult> {
    // 1) Fetch a single-use challenge + the account's pinned PBKDF2 iteration count.
    const { challenge, pbkdf2Iterations } = await this.post<{ challenge: string; pbkdf2Iterations?: number }>(
      "challenge",
      { email: params.email },
    );
    // 2) Re-derive the appKey (legacy accounts: 100k fallback) and sign the challenge
    //    with the derived auth keypair — the server stores only the matching public key.
    const iterations = pbkdf2Iterations ?? 100_000;
    const appKey = deriveAppKeyFromPasskey(params.passkey, params.email, iterations, this.config.appId);
    const signature = signAuthChallenge(appKey, challenge);
    const result = await this.post<AuthResult>("login", { email: params.email, signature, challenge });
    setSession({
      publicKey: result.publicKey,
      authToken: result.authToken,
      appKey,
      email: params.email,
      pbkdf2Iterations: iterations,
    });
    return result;
  }

  // --- Web3 wallet ---

  /**
   * Wallet handshake. Two signatures with distinct purposes:
   *  - over the random challenge → proves ownership for auth (replay-safe, sent to server)
   *  - over a FIXED message → derives the deterministic encryption key (stays client-side)
   * Using the fixed message for the key is what lets the same wallets decrypt on
   * every login and device.
   */
  private async walletHandshake(
    publicKey: string,
    signMessage: (message: Uint8Array) => Promise<Uint8Array>,
  ): Promise<{ appKey: string; signatureHex: string; challenge: string }> {
    const { challenge } = await this.post<{ challenge: string }>("challenge", { publicKey });
    const enc = new TextEncoder();
    const authSig = await signMessage(enc.encode(walletLoginMessage(challenge)));
    const keySig = await signMessage(enc.encode(walletAppKeyMessage(this.config.appId)));
    return {
      appKey: deriveAppKeyFromSignature(bytesToHex(keySig)),
      signatureHex: bytesToHex(authSig),
      challenge,
    };
  }

  /** Log in an already-registered Web3 wallet. */
  async loginWithWallet(params: {
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
    );
    const result = await this.post<AuthResult>("login-wallet", {
      publicKey: params.publicKey,
      signature: signatureHex,
      challenge,
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return result;
  }

  /**
   * Connect a Web3 wallet in one round trip: logs in if the wallet is known,
   * otherwise registers it with freshly generated, client-encrypted wallets.
   * Prompts two signatures (verify ownership + derive the encryption key).
   */
  async connectWallet(params: {
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
    );
    // Sent only if the wallet is new; the server ignores it for returning wallets.
    const bundle = await generateWalletBundle({ appKey, ...this.walletGen });
    const result = await this.post<AuthResult>("connect-wallet", {
      publicKey: params.publicKey,
      signature: signatureHex,
      challenge,
      wallets: flattenBundle(bundle),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return result;
  }

  /** Register a Web3 wallet, generating any additional signing wallets client-side. */
  async registerWithWallet(params: {
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
    );
    // The connected wallet is the funds identity; generate extra (e.g. signing) wallets.
    const bundle = await generateWalletBundle({ appKey, ...this.walletGen });
    const result = await this.post<AuthResult>("register", {
      publicKey: params.publicKey,
      authMethod: "wallet",
      wallets: flattenBundle(bundle),
      signature: signatureHex,
      challenge,
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return result;
  }

  // --- Biometric ---

  /** Register a biometric (passkey) account; PRF/gate secret becomes the app key. */
  async registerWithBiometric(params: {
    userName: string;
  }): Promise<{ result: AuthResult; registration: PasskeyRegistration }> {
    const registration = await registerPasskey(this.config.webauthn, params.userName);
    const appKey = await derivePasskeySecret(registration);
    const bundle = await generateWalletBundle({ appKey, ...this.walletGen });
    const identity =
      bundle.solana?.funds ?? Object.values(bundle.solana ?? {})[0] ?? Object.values(bundle.evm ?? {})[0];
    if (!identity) throw new Error("walletGen must produce at least one wallet");

    // Internal, login-resolvable identifier derived from the credential (never shown to the user).
    const internalEmail = biometricEmail(registration);
    const result = await this.post<AuthResult>("register", {
      publicKey: identity.publicKey,
      email: internalEmail,
      authMethod: "biometric",
      // Auth keypair derived from the PRF/gate secret; server stores only its public key.
      authPublicKey: deriveAuthPublicKey(appKey),
      wallets: flattenBundle(bundle),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return { result, registration };
  }

  /** Biometric re-login: unlock the passkey secret and authenticate. */
  async loginWithBiometric(params: { registration: PasskeyRegistration }): Promise<AuthResult> {
    // Resolve the internal identity, fetch a challenge, then prove control by signing it
    // with the auth keypair derived from the PRF/gate secret (released by Touch ID).
    const email = biometricEmail(params.registration);
    const { challenge } = await this.post<{ challenge: string }>("challenge", { email });
    const appKey = await derivePasskeySecret(params.registration);
    const signature = signAuthChallenge(appKey, challenge);
    const result = await this.post<AuthResult>("login", { email, signature, challenge });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return result;
  }

  // --- Optional biometric UNLOCK (any account) ---
  //
  // Thin delegations so createAuthClient() consumers get the same API as the
  // standalone client functions. See biometricUnlock.ts for the full contract.
  // NOTE: this is the OPTIONAL unlock layer (`{ biometricUnlock }`), NOT the
  // biometric-PRIMARY flow (registerWithBiometric / `{ registration }`).

  /** True if a biometric-unlock blob is registered on this device. Sync. */
  hasBiometricUnlock(): boolean {
    return hasBiometricUnlock();
  }

  /**
   * Wrap the CURRENT vault app key under a freshly-registered passkey and persist
   * it (vault must be unlocked, else VaultLockedError). Returns the registration
   * to persist for unlockViaBiometric/disableBiometricUnlock.
   */
  enableBiometricUnlock(userName: string): Promise<PasskeyRegistration> {
    return enableBiometricUnlock(this.config.webauthn, userName);
  }

  /** Touch ID -> unwrap the stored app key -> re-arm the vault for any account. */
  unlockViaBiometric(registration: PasskeyRegistration): Promise<void> {
    return unlockViaBiometric(registration);
  }

  /** Remove the wrapped blob + gate secret + on-device marker for a credential. */
  disableBiometricUnlock(registration: PasskeyRegistration): Promise<void> {
    return disableBiometricUnlock(registration);
  }

  /**
   * Log out: best-effort server-side token revocation, then clear local state.
   * The revocation request is fired without awaiting (capturing the headers before
   * they're cleared) so logout is instant and never blocked by the network. It uses
   * `keepalive: true` so the request still lands when logout coincides with the page
   * unloading (sendBeacon can't carry our auth headers); if it fails, the token still
   * dies at its server-side TTL. clearSession() then removes the shared-localStorage
   * token, which fires a `storage` event that locks sibling tabs (CLIENTVAULT-7).
   */
  logout(): void {
    const headers = this.authHeaders();
    if (getAuthToken()) {
      void fetch(`${this.opts.apiBaseUrl}/logout`, { method: "POST", headers, keepalive: true }).catch(() => {
        /* best-effort — TTL is the backstop */
      });
    }
    clearSession();
  }
}

/** Convenience factory. */
export function createAuthClient(opts: AuthClientOptions): AuthClient {
  return new AuthClient(opts);
}
