// Framework-agnostic core: types, config, crypto. No DOM/Node/React assumptions
// beyond WebCrypto's getRandomValues.
import { normalizeOrigin, parseOrigin } from "./config.js";

export * from "./types.js";
export * from "./config.js";
export * from "./crypto.js";
export * from "./offchainMessage.js";

/**
 * The statement line of {@link walletLoginMessage}. SIWS allows only RFC 3986
 * reserved/unreserved characters plus space and no line breaks, and Phantom rejects a
 * statement containing an em dash, curly quote or NBSP — keep copy edits to plain ASCII.
 */
export const WALLET_LOGIN_STATEMENT =
  "Sign in to prove you own this wallet. This request does not send a transaction or cost any fees.";

/** SIWS `message-address`: 32–44 base58 characters. */
const SIWS_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/** SIWS `nonce`: at least 8 letters or digits. `generateChallenge()` emits 64 hex. */
const SIWS_NONCE = /^[A-Za-z0-9]{8,}$/;

/**
 * The Sign In With Solana (SIWS) message a wallet signs to prove ownership during Web3
 * login and registration:
 *
 *     www.tetrac.xyz wants you to sign in with your Solana account:
 *     <address>
 *
 *     <WALLET_LOGIN_STATEMENT>
 *
 *     URI: https://www.tetrac.xyz
 *     Version: 1
 *     Nonce: <challenge>
 *
 * It must be valid SIWS. Phantom parses any payload that looks like SIWS and refuses to
 * display one that fails its field checks, so the builder throws rather than emit a
 * malformed field. A valid message also lets the wallet compare line 1 with the page
 * that is asking for the signature.
 *
 * Bound to `origin` — the site the signature is FOR. The client builds the message from
 * its REAL `window.location.origin` and the server rebuilds it from its OWN configured
 * origin (never from the request), so the two agree only when the page asking for the
 * signature is the site verifying it. `/challenge` is unauthenticated and accepts any
 * public key, so without this a phishing page could fetch a real challenge from a victim
 * app, collect a signature, and relay it to log in as the victim. Line 1 carries the
 * bare authority, as SIWS requires; the scheme stays in the signed bytes on the `URI:`
 * line, so http and https never share a signature. Both come from one URL parse.
 *
 * Bound to `address` — the signer's base58 public key. The server rebuilds it from the
 * key it verifies under.
 *
 * Named fields: all three inputs are strings, and transposed positionally they would
 * still build a well-formed message that never verifies.
 */
export function walletLoginMessage(input: { challenge: string; origin: string; address: string }): string {
  const url = parseOrigin(input.origin);
  if (!SIWS_ADDRESS.test(input.address)) {
    throw new Error("[tetrac] walletLoginMessage: address must be a base58 public key.");
  }
  if (!SIWS_NONCE.test(input.challenge)) {
    throw new Error("[tetrac] walletLoginMessage: challenge must be at least 8 letters or digits.");
  }
  return (
    `${url.host} wants you to sign in with your Solana account:\n` +
    `${input.address}\n\n` +
    `${WALLET_LOGIN_STATEMENT}\n\n` +
    `URI: ${url.origin}\n` +
    `Version: 1\n` +
    `Nonce: ${input.challenge}`
  );
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
