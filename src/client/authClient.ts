// High-level browser auth client. Orchestrates key derivation, client-side wallet
// generation, the API round-trips, and session storage for all three methods.
import {
  resolveConfig,
  APP_ID_HEADER,
  PBKDF2_ITERATIONS,
  type AuthConfig,
  type DeepPartial,
} from "../core/config.js";
import { deriveAppKeyFromPasskey, deriveAppKeyFromSignature } from "../core/crypto.js";
import { deriveAuthPublicKey, signAuthChallenge } from "./authKey.js";
import { walletLoginMessage, walletAppKeyMessage, walletAppKeyMessageHw } from "../core/index.js";
import type { AuthResult, EncryptedWallet, OffchainEnvelope, UserData, WalletRole } from "../core/types.js";

/**
 * A connected wallet's message signer.
 *
 * The options bag is HARDWARE-ONLY and safe to ignore: software wallets (Phantom,
 * Solflare, a wallet-adapter) take one argument and always have. A Ledger signer honours
 * `envelope` to pin the off-chain layout for app-key derivation, and reports the layout it
 * settled on via `onEnvelope` at registration. See OffchainEnvelope for why that matters.
 */
export type WalletSignMessage = (
  message: Uint8Array,
  opts?: { envelope?: OffchainEnvelope; onEnvelope?: (e: OffchainEnvelope) => void },
) => Promise<Uint8Array>;
import { generateWalletBundle, flattenBundle, decryptWalletSecret } from "./wallet.js";
import {
  setSession,
  clearSession,
  authHeaders,
  armAppKey,
  getAuthToken,
  getEmail,
  getPbkdf2Iterations,
  getOffchainEnvelope,
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
  | {
      signMessage: WalletSignMessage;
      /** Hardware (Ledger) account: re-derive the app key from the newline-free message. */
      hardwareWallet?: boolean;
    }
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

/**
 * The wallet bundle to generate for a WEB3 (connected-wallet) login.
 *
 * For email/biometric accounts the embedded Solana `funds` wallet IS the account
 * identity — it is generated here and its public key becomes `UserData.publicKey`.
 *
 * For a Web3 login that is NOT true: the user's connected wallet (Phantom, Solflare,
 * Ledger…) is already their Solana funds wallet, and it becomes `UserData.publicKey`.
 * Generating a SECOND Solana `funds` wallet gives them a wallet they never asked for,
 * whose private key the SDK holds and will happily reveal, and — worse — which
 * `useActiveWallet()`/`useWallets()` then surface as "the Solana funds wallet",
 * shadowing the real one. An app rendering that as a deposit address would send the
 * user's funds to a wallet they don't know they own. (v0.5.1)
 *
 * So: strip the `funds` role from Solana. Other roles still make sense — a Solana
 * `signing` (hot/session) wallet, and EVM wallets, are genuinely additional keys the
 * connected Solana wallet cannot provide.
 */
function web3WalletGen(gen: WalletGenConfig): WalletGenConfig {
  const solana = gen.solana?.filter((role) => role !== "funds");
  return { ...gen, solana: solana?.length ? solana : undefined };
}

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

  /**
   * The origin every wallet message is built from — read from `window.location`, NOT
   * from config.
   *
   * That distinction is the fix, not a detail. If this came from config, a hostile page
   * could set `{ appId: "victim.app", origin: "https://victim.app" }` and reproduce the
   * victim deployment's exact app-key message, harvesting a signature whose SHA-256
   * decrypts that user's whole wallet bundle. `window.location.origin` is the one value
   * the page cannot lie about, and it is what the user sees in the address bar while
   * the signing prompt names the same site.
   */
  private clientOrigin(): string {
    const origin = typeof window !== "undefined" ? window.location?.origin : undefined;
    if (!origin) {
      throw new Error("[tetrac] Web3 wallet flows require a browser origin (window.location.origin).");
    }
    return origin;
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
      const keyMessage = creds.hardwareWallet
        ? walletAppKeyMessageHw(this.config.appId, this.clientOrigin())
        : walletAppKeyMessage(this.config.appId, this.clientOrigin());
      // Pin the layout this account registered under. Re-auth derives the SAME app key, so
      // letting it cascade here would hand back a different key the moment a firmware
      // update flips the device — and unlock() without `validateWith` arms it silently.
      const pinned = creds.hardwareWallet ? getOffchainEnvelope() : null;
      const sig = await creds.signMessage(
        new TextEncoder().encode(keyMessage),
        pinned ? { envelope: pinned as OffchainEnvelope } : undefined,
      );
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
    return { ...authHeaders(), [APP_ID_HEADER]: this.config.appId };
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
    const { challenge, pbkdf2Iterations } = await this.post<{ challenge: string; pbkdf2Iterations: number }>(
      "challenge",
      { email: params.email },
    );
    // 2) Re-derive the appKey with the count the SERVER pinned, and sign the challenge with
    //    the derived auth keypair — the server stores only the matching public key.
    //
    //    No local fallback. /challenge always returns a count now (it has to: an omitted
    //    field distinguished a real account from the dummy issued for an unknown email, so
    //    the omission was an enumeration oracle). Guessing a count here would silently
    //    derive the wrong app key and leave the wallets undecryptable, which is worse than
    //    failing, and the server is the only side that knows what the account was pinned to.
    const iterations = pbkdf2Iterations;
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
    signMessage: WalletSignMessage,
    hardwareWallet = false,
  ): Promise<{
    appKey: string;
    signatureHex: string;
    challenge: string;
    offchainEnvelope?: OffchainEnvelope;
  }> {
    // /challenge also returns the account's PINNED off-chain envelope, when it has one —
    // the hardware counterpart of pbkdf2Iterations, and app-key derivation input just the
    // same. Absent for a wallet registering for the first time.
    const { challenge, offchainEnvelope: pinned } = await this.post<{
      challenge: string;
      offchainEnvelope?: OffchainEnvelope;
    }>("challenge", { publicKey });
    const enc = new TextEncoder();
    // The AUTH signature may cascade freely: it is challenge-bound and stateless, so which
    // envelope produced it does not matter — the server accepts any of them.
    const authSig = await signMessage(enc.encode(walletLoginMessage(challenge, this.clientOrigin())));
    // Hardware wallets derive the key from the newline-free message so the device
    // can clear-sign it (a Ledger rejects newline content / forces blind signing).
    const keyMessage = hardwareWallet
      ? walletAppKeyMessageHw(this.config.appId, this.clientOrigin())
      : walletAppKeyMessage(this.config.appId, this.clientOrigin());

    // The KEY signature must NOT cascade. Pin the recorded layout; on first registration
    // there is none yet, so let it cascade once and capture what the device chose.
    let used: OffchainEnvelope | undefined = pinned;
    const keySig = await signMessage(
      enc.encode(keyMessage),
      hardwareWallet ? { envelope: pinned, onEnvelope: (e) => (used = e) } : undefined,
    );
    return {
      appKey: deriveAppKeyFromSignature(bytesToHex(keySig)),
      signatureHex: bytesToHex(authSig),
      challenge,
      offchainEnvelope: hardwareWallet ? used : undefined,
    };
  }

  /** Log in an already-registered Web3 wallet. */
  async loginWithWallet(params: {
    publicKey: string;
    signMessage: WalletSignMessage;
    /** Set true for a hardware wallet (Ledger) — uses the newline-free app-key message. */
    hardwareWallet?: boolean;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge, offchainEnvelope } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
      params.hardwareWallet,
    );
    const result = await this.post<AuthResult>("login-wallet", {
      publicKey: params.publicKey,
      signature: signatureHex,
      challenge,
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey, offchainEnvelope });
    return result;
  }

  /**
   * Connect a Web3 wallet in one round trip: logs in if the wallet is known,
   * otherwise registers it with freshly generated, client-encrypted wallets.
   * Prompts two signatures (verify ownership + derive the encryption key).
   */
  async connectWallet(params: {
    publicKey: string;
    signMessage: WalletSignMessage;
    /** Set true for a hardware wallet (Ledger) — uses the newline-free app-key message. */
    hardwareWallet?: boolean;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge, offchainEnvelope } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
      params.hardwareWallet,
    );
    // Sent only if the wallet is new; the server ignores it for returning wallets.
    // NO embedded Solana `funds` wallet: the wallet they just connected IS it (web3WalletGen).
    const bundle = await generateWalletBundle({ appKey, ...web3WalletGen(this.walletGen) });
    const result = await this.post<AuthResult>("connect-wallet", {
      publicKey: params.publicKey,
      signature: signatureHex,
      challenge,
      wallets: flattenBundle(bundle),
      // Pin the layout this device signed under, so future derivations do not cascade.
      offchainEnvelope,
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey, offchainEnvelope });
    return result;
  }

  /** Register a Web3 wallet, generating any additional signing wallets client-side. */
  async registerWithWallet(params: {
    publicKey: string;
    signMessage: WalletSignMessage;
    /** Set true for a hardware wallet (Ledger) — uses the newline-free app-key message. */
    hardwareWallet?: boolean;
  }): Promise<AuthResult> {
    const { appKey, signatureHex, challenge, offchainEnvelope } = await this.walletHandshake(
      params.publicKey,
      params.signMessage,
      params.hardwareWallet,
    );
    // The connected wallet IS the Solana funds identity — generate only the extra wallets
    // (Solana `signing`, EVM). web3WalletGen strips the redundant Solana `funds` role.
    const bundle = await generateWalletBundle({ appKey, ...web3WalletGen(this.walletGen) });
    const result = await this.post<AuthResult>("register", {
      publicKey: params.publicKey,
      authMethod: "wallet",
      wallets: flattenBundle(bundle),
      signature: signatureHex,
      challenge,
      // Pin the layout this device signed under, so future derivations do not cascade.
      offchainEnvelope,
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey, offchainEnvelope });
    return result;
  }

  // --- Biometric ---

  /** Register a biometric (passkey) account; PRF secret becomes the app key. */
  async registerWithBiometric(params: {
    userName: string;
  }): Promise<{ result: AuthResult; registration: PasskeyRegistration }> {
    // Throws PrfUnavailableError on an authenticator without PRF — the derived secret IS
    // this account's app key, so there is no passkey to retype and no wallet to re-sign.
    // Callers should catch it and offer email or wallet registration instead.
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
      // Auth keypair derived from the PRF secret; server stores only its public key.
      authPublicKey: deriveAuthPublicKey(appKey),
      wallets: flattenBundle(bundle),
    });
    setSession({ publicKey: result.publicKey, authToken: result.authToken, appKey });
    return { result, registration };
  }

  /** Biometric re-login: unlock the passkey secret and authenticate. */
  async loginWithBiometric(params: { registration: PasskeyRegistration }): Promise<AuthResult> {
    // Resolve the internal identity, fetch a challenge, then prove control by signing it
    // with the auth keypair derived from the PRF secret (released by Touch ID).
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
