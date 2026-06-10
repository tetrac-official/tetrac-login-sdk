// High-level browser auth client. Orchestrates key derivation, client-side wallet
// generation, the API round-trips, and session storage for all three methods.
import { resolveConfig, type AuthConfig, type DeepPartial } from "../core/config.js";
import {
  deriveAppKeyFromPasskey,
  deriveAppKeyFromSignature,
  hashPasskey,
} from "../core/crypto.js";
import { walletLoginMessage, walletAppKeyMessage } from "../core/index.js";
import type { AuthResult, EncryptedWallet, UserData, WalletRole } from "../core/types.js";
import { generateWalletBundle, flattenBundle, decryptWalletSecret } from "./wallet.js";
import { setSession, clearSession, authHeaders, armAppKey, getAuthToken, getEmail, configureVault } from "./session.js";
import { registerPasskey, derivePasskeySecret, type PasskeyRegistration } from "./webauthn.js";

/**
 * Credentials for a re-authentication ceremony (unlock or reveal). Exactly one
 * shape is supplied, matching the account's auth method:
 *  - email:     { passkey }      (email is read from the session)
 *  - wallet:    { signMessage }  (re-signs the fixed app-key message)
 *  - biometric: { registration } (fresh WebAuthn assertion → PRF secret)
 */
export type ReauthCredentials =
  | { passkey: string }
  | { signMessage: (message: Uint8Array) => Promise<Uint8Array> }
  | { registration: PasskeyRegistration };

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
    // Apply the auto-lock / storage policy to the vault (idempotent).
    configureVault({
      autoLockMs: this.config.autoLockMs,
      storageMode: this.config.appKeyStorage,
      lockOnHide: this.config.lockOnHide,
    });
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
      return deriveAppKeyFromPasskey(creds.passkey, email, this.config.pbkdf2Iterations);
    }
    if ("signMessage" in creds) {
      const sig = await creds.signMessage(new TextEncoder().encode(walletAppKeyMessage()));
      return deriveAppKeyFromSignature(bytesToHex(sig));
    }
    if ("registration" in creds) {
      return derivePasskeySecret(creds.registration);
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
        decryptWalletSecret(validateWith, appKey);
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
      return decryptWalletSecret(wallet, appKey);
    } catch {
      throw new Error("Re-authentication failed — wrong credentials");
    }
  }

  private async post<T>(path: string, body: unknown, withAuth = false): Promise<T> {
    const res = await fetch(`${this.opts.apiBaseUrl}/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(withAuth ? authHeaders() : {}) },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as { error?: string }).error ?? `Request failed (${res.status})`);
    return data as T;
  }

  /** Fetch the authenticated user's full record (identity + encrypted wallets). */
  async fetchUserData(): Promise<UserData | null> {
    const res = await fetch(`${this.opts.apiBaseUrl}/user-data`, { headers: authHeaders() });
    if (res.status === 401) return null;
    if (!res.ok) throw new Error(`user-data failed (${res.status})`);
    const data = (await res.json().catch(() => ({}))) as { user?: UserData };
    return data.user ?? null;
  }

  // --- Email + passkey ---

  /** Register an email/passkey account; generates and encrypts wallets client-side. */
  async registerWithEmail(params: { email: string; passkey: string }): Promise<AuthResult> {
    const appKey = deriveAppKeyFromPasskey(params.passkey, params.email, this.config.pbkdf2Iterations);
    const bundle = generateWalletBundle({ appKey, ...this.walletGen });
    const identity = bundle.solana?.funds ?? Object.values(bundle.solana ?? {})[0] ?? Object.values(bundle.evm ?? {})[0];
    if (!identity) throw new Error("walletGen must produce at least one wallet");

    const result = await this.post<AuthResult>("register", {
      publicKey: identity.publicKey,
      email: params.email,
      passkeyHash: hashPasskey(params.passkey),
      authMethod: "email",
      wallets: flattenBundle(bundle),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey, email: params.email });
    return result;
  }

  /** Log in with email + passkey. Re-derives the app key to unlock wallets. */
  async loginWithEmail(params: { email: string; passkey: string }): Promise<AuthResult> {
    const appKey = deriveAppKeyFromPasskey(params.passkey, params.email, this.config.pbkdf2Iterations);
    const result = await this.post<AuthResult>("login", {
      email: params.email,
      passkeyHash: hashPasskey(params.passkey),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey, email: params.email });
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
    const keySig = await signMessage(enc.encode(walletAppKeyMessage()));
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
    const { appKey, signatureHex, challenge } = await this.walletHandshake(params.publicKey, params.signMessage);
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
    const { appKey, signatureHex, challenge } = await this.walletHandshake(params.publicKey, params.signMessage);
    // Sent only if the wallet is new; the server ignores it for returning wallets.
    const bundle = generateWalletBundle({ appKey, ...this.walletGen });
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
    const { appKey, signatureHex, challenge } = await this.walletHandshake(params.publicKey, params.signMessage);
    // The connected wallet is the funds identity; generate extra (e.g. signing) wallets.
    const bundle = generateWalletBundle({ appKey, ...this.walletGen });
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
  async registerWithBiometric(params: { userName: string }): Promise<{ result: AuthResult; registration: PasskeyRegistration }> {
    const registration = await registerPasskey(this.config.webauthn, params.userName);
    const appKey = await derivePasskeySecret(registration);
    const bundle = generateWalletBundle({ appKey, ...this.walletGen });
    const identity = bundle.solana?.funds ?? Object.values(bundle.solana ?? {})[0] ?? Object.values(bundle.evm ?? {})[0];
    if (!identity) throw new Error("walletGen must produce at least one wallet");

    // Internal, login-resolvable identifier derived from the credential (never shown to the user).
    const internalEmail = biometricEmail(registration);
    const result = await this.post<AuthResult>("register", {
      publicKey: identity.publicKey,
      email: internalEmail,
      authMethod: "biometric",
      // Bind the credential to the account via a hash so re-login can verify.
      passkeyHash: hashPasskey(appKey),
      wallets: flattenBundle(bundle),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return { result, registration };
  }

  /** Biometric re-login: unlock the passkey secret and authenticate. */
  async loginWithBiometric(params: { registration: PasskeyRegistration }): Promise<AuthResult> {
    const appKey = await derivePasskeySecret(params.registration);
    const result = await this.post<AuthResult>("login", {
      // Resolve the same internal identity created at registration.
      email: biometricEmail(params.registration),
      passkeyHash: hashPasskey(appKey),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return result;
  }

  /**
   * Log out: best-effort server-side token revocation, then clear local state.
   * The revocation request is fired without awaiting (capturing the headers
   * before they're cleared) so logout is instant and never blocked by the
   * network; if it fails, the token still dies at its server-side TTL.
   */
  logout(): void {
    const headers = authHeaders();
    if (getAuthToken()) {
      void fetch(`${this.opts.apiBaseUrl}/logout`, { method: "POST", headers }).catch(() => {
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
