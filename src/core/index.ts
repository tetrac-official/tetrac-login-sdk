// Framework-agnostic core: types, config, crypto. No DOM/Node/React assumptions
// beyond WebCrypto's getRandomValues.
import { normalizeOrigin } from "./config.js";

export * from "./types.js";
export * from "./config.js";
export * from "./crypto.js";
export * from "./offchainMessage.js";

/**
 * The canonical message a wallet signs to prove ownership during Web3 login (auth).
 *
 * SIWE-shaped and bound to `origin` — the site the signature is FOR. This binding is
 * the whole security property: the client builds the message from its REAL
 * `window.location.origin`, and the server rebuilds it from its OWN configured origin
 * (never from the request), so the two only agree when the page asking for the
 * signature is the site verifying it.
 *
 * Without it, the message was a bare challenge — identical bytes on every deployment,
 * naming no site. Since `/challenge` is unauthenticated and accepts any public key, a
 * phishing page could fetch a real challenge from a victim app, collect a signature
 * over that generic text, and relay it to log in as the victim. The prompt gave the
 * user nothing to distinguish "sign in to the site I'm on" from "sign in to some
 * other site". Both signatures were genuine, so every downstream check passed.
 */
export function walletLoginMessage(challenge: string, origin: string): string {
  const site = normalizeOrigin(origin);
  return `${site} wants you to sign in with your Solana account.\n\nURI: ${site}\nNonce: ${challenge}`;
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
 * The full message a Web3 wallet signs to derive its app key, DOMAIN-BOUND by BOTH
 * `appId` and `origin`.
 *
 * `appId` alone was not enough. It is chosen by the CLIENT, so a hostile page could
 * simply set `appId: "victim.app"` and collect a signature that derives the victim
 * app's real key — SHA-256 of which decrypts that user's entire wallet bundle. The
 * origin cannot be spoofed the same way: it is the page the user is actually on, and
 * it is rendered in the signing prompt.
 *
 * Deterministic for a given (appId, origin) pair, so login and recovery stay stable.
 * Both are therefore permanent: changing either re-derives every app key.
 */
export function walletAppKeyMessage(appId: string, origin: string): string {
  return `${WALLET_APP_KEY_MESSAGE}\n\nApp: ${appId}\nSite: ${normalizeOrigin(origin)}`;
}

/**
 * Newline-free variant of {@link WALLET_APP_KEY_MESSAGE} for HARDWARE wallets.
 *
 * A Ledger signs Solana off-chain messages, and its legacy firmware only accepts
 * printable-ASCII content in the no-blind-sign format — a newline (0x0a) makes the
 * device reject the message (status 0x6a82) or demand Blind Signing. This message
 * is pure printable ASCII, so a Ledger derives its app key with a normal,
 * clear-signed prompt. It is a SEPARATE domain string (CRYPTO_SPEC §7): a hardware
 * account that derives its key from THIS message must always re-derive from it, so
 * callers pass `hardwareWallet: true` consistently at register and login.
 */
export const WALLET_APP_KEY_MESSAGE_HW =
  "Unlock your encrypted TTC wallet keys. Only sign this on a site you trust. This signature never leaves your device.";

/** Domain-bound (`appId` + `origin`) hardware app-key message — the newline-free
 *  counterpart of {@link walletAppKeyMessage}. An origin is printable ASCII, so this
 *  stays clear-signable on a Ledger. */
export function walletAppKeyMessageHw(appId: string, origin: string): string {
  return `${WALLET_APP_KEY_MESSAGE_HW} App: ${appId} Site: ${normalizeOrigin(origin)}`;
}

/**
 * Message an email/biometric account signs (with its derived ed25519 auth keypair)
 * to log in. The challenge is single-use and server-issued; signing it proves control
 * of the account's auth key without the server ever storing a passkey hash.
 */
export function authLoginMessage(challenge: string): string {
  return `Sign in to your TTC account: ${challenge}`;
}
