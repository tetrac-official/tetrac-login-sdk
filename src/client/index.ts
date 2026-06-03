// Browser-only entry: wallet generation, encryption, sessions, WebAuthn, auth client.
export {
  generateWalletBundle,
  flattenBundle,
  decryptWalletSecret,
  toSolanaKeypair,
  withDecryptedKey,
  type GenerateWalletBundleInput,
} from "./wallet.js";
export {
  setSession,
  clearSession,
  getAuthToken,
  getPublicKey,
  getEmail,
  getAppKey,
  getAuthStatus,
  authHeaders,
} from "./session.js";
export {
  isBiometricAvailable,
  registerPasskey,
  derivePasskeySecret,
  type PasskeyRegistration,
} from "./webauthn.js";
export {
  AuthClient,
  createAuthClient,
  type AuthClientOptions,
  type WalletGenConfig,
} from "./authClient.js";
