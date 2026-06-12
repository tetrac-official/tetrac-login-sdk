// Framework-agnostic core: types, config, crypto. No DOM/Node/React assumptions
// beyond WebCrypto's getRandomValues.
export * from "./types.js";
export * from "./config.js";
export * from "./crypto.js";

/** The canonical message a wallet signs to prove ownership during Web3 login (auth). */
export function walletLoginMessage(challenge: string): string {
  return `Sign this message to verify wallet ownership: ${challenge}`;
}

/**
 * Base text of the message a wallet signs to derive its encryption (app) key. It
 * must be constant per app — NOT the random challenge — so the derived key is
 * deterministic and the same wallets decrypt on every login and device. The
 * signature never leaves the client; only its SHA-256 hash becomes the key.
 */
export const WALLET_APP_KEY_MESSAGE =
  "Unlock your encrypted TTC wallet keys.\n\nOnly sign this on a site you trust. This signature never leaves your device.";

/**
 * The full message a Web3 wallet signs to derive its app key, DOMAIN-BOUND by
 * `appId` (CRYPTO-2/H4 / WI-14): the same wallet signs a DIFFERENT message per app,
 * so it derives a different app key per app. A malicious site that coerces a
 * signature cannot reproduce another app's key. Deterministic for a given appId, so
 * recovery/login stays stable. Default "ttc" must match DEFAULT_CONFIG.appId.
 */
export function walletAppKeyMessage(appId = "ttc"): string {
  return `${WALLET_APP_KEY_MESSAGE}\n\nApp: ${appId}`;
}

/**
 * Message an email/biometric account signs (with its derived ed25519 auth keypair)
 * to log in. The challenge is single-use and server-issued; signing it proves control
 * of the account's auth key without the server ever storing a passkey hash.
 */
export function authLoginMessage(challenge: string): string {
  return `Sign in to your TTC account: ${challenge}`;
}
