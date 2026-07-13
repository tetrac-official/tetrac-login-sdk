// Shared types used across every layer of the SDK.

/** Supported chains for client-side wallet generation. */
export type Chain = "solana" | "evm";

/**
 * Standard wallet roles. `funds` holds assets; `signing` is the agent wallet
 * used for delegated signing (so the funds key is never exposed to sign flows).
 * Consumers may also use arbitrary custom role strings.
 */
export type WalletRole = "funds" | "signing" | (string & {});

/** Authentication method used to establish the session. */
export type AuthMethod = "email" | "wallet" | "biometric";

/** Client-facing auth status, mirroring next-ttc's getAuthStatus(). */
export type AuthStatus = "authenticated" | "session_expired" | "unauthenticated";

/** A single generated keypair after client-side encryption. */
export interface EncryptedWallet {
  chain: Chain;
  role: WalletRole;
  /** base58 (Solana) or 0x-hex (EVM) public identifier — safe to send to the server. */
  publicKey: string;
  /** Ciphertext of the secret key (AES-256-GCM, "iv:ct+tag" b64url). Never plaintext. */
  encryptedSecret: string;
}

/** Per-chain map of role -> encrypted wallet. */
export type ChainWallets = Record<string, EncryptedWallet>;

/** Result of generateWalletBundle(): chain -> role -> wallet. */
export interface GeneratedWalletBundle {
  solana?: ChainWallets;
  evm?: ChainWallets;
}

/** Payload stored server-side under pubKey:{appId}:{publicKey}. */
export interface UserData {
  /**
   * The app this record belongs to (multi-app isolation, v0.4.0). Pinned at
   * registration and baked into every storage key for this user, so two apps
   * sharing one Redis/Upstash DB never read or overwrite each other's records.
   * Defaults to the server's config.appId when a request omits it (single-app).
   */
  appId: string;
  publicKey: string;
  email?: string;
  /**
   * ed25519 auth public key (hex) for email/biometric accounts — the ONLY auth
   * credential the server stores. Login proves control by signing a challenge with
   * the matching key, derived client-side from the appKey. Wallet accounts instead
   * authenticate with their own on-chain key, so they have no authPublicKey.
   */
  authPublicKey?: string;
  authMethod: AuthMethod;
  /** Encrypted wallet blobs, flattened for storage. */
  wallets: EncryptedWallet[];
  createdAt: number;
  /** PBKDF2 iteration count used to derive the app key (email users). Pinned at registration. */
  pbkdf2Iterations?: number;
  /**
   * SHA-256 of the user's CURRENT session token (v0.5.0) — never the token itself.
   * Used solely to revoke the previous session on re-login (the digest IS the session
   * key, so the raw token is not needed to find it).
   *
   * Before v0.5.0 this record instead carried a raw `authToken` bearer token, which
   * meant a read of the store yielded live, replayable credentials for every logged-in
   * user. That field is no longer written, and is scrubbed on the next write to a
   * record that still has it (see issueSession). The raw token now exists only in the
   * client's hands, delivered once via AuthResult.authToken.
   */
  authTokenHash?: string;
  [extra: string]: unknown;
}

/** Response returned by login/register endpoints. */
export interface AuthResult {
  publicKey: string;
  authToken: string;
  user: UserData;
}
