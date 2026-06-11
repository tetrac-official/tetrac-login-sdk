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
 * Fixed message a wallet signs to derive its encryption (app) key. It must be
 * constant — NOT the random challenge — so the derived key is deterministic and
 * the same wallets decrypt on every login and every device. The signature never
 * leaves the client; only its SHA-256 hash becomes the key.
 */
export const WALLET_APP_KEY_MESSAGE =
  "Unlock your encrypted TTC wallet keys.\n\nOnly sign this on a site you trust. This signature never leaves your device.";

export function walletAppKeyMessage(): string {
  return WALLET_APP_KEY_MESSAGE;
}

/**
 * Message an email/biometric account signs (with its derived ed25519 auth keypair)
 * to log in. The challenge is single-use and server-issued; signing it proves control
 * of the account's auth key without the server ever storing a passkey hash.
 */
export function authLoginMessage(challenge: string): string {
  return `Sign in to your TTC account: ${challenge}`;
}
