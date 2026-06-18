// Client-side, non-custodial wallet generation. Keys are created in the browser
// and AES-encrypted under the app key BEFORE anything is sent to the server.
import { Keypair } from "@solana/web3.js";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type {
  Chain,
  WalletRole,
  EncryptedWallet,
  GeneratedWalletBundle,
  ChainWallets,
} from "../core/types.js";
import { encryptSecret, decryptSecret } from "../core/crypto.js";

export interface GenerateWalletBundleInput {
  /** The derived app key (from passkey+email or wallet signature). Never sent to the server. */
  appKey: string;
  /** Solana roles to generate, e.g. ["funds", "signing"]. Omit to skip Solana. */
  solana?: WalletRole[];
  /** EVM roles to generate, e.g. ["funds", "signing"]. Omit to skip EVM. */
  evm?: WalletRole[];
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Generate one Solana keypair and return its public key + encrypted secret (hex of the 64-byte secret). */
async function generateSolanaWallet(role: WalletRole, appKey: string): Promise<EncryptedWallet> {
  const kp = Keypair.generate();
  const secretHex = bytesToHex(kp.secretKey);
  return {
    chain: "solana",
    role,
    publicKey: kp.publicKey.toBase58(),
    encryptedSecret: await encryptSecret(secretHex, appKey),
  };
}

/** Generate one EVM keypair via viem and return its address + encrypted private key (0x hex). */
async function generateEvmWallet(role: WalletRole, appKey: string): Promise<EncryptedWallet> {
  const privateKey = generatePrivateKey(); // 0x-prefixed 32-byte hex
  const account = privateKeyToAccount(privateKey);
  return {
    chain: "evm",
    role,
    publicKey: account.address,
    encryptedSecret: await encryptSecret(privateKey, appKey),
  };
}

/** Generate a role-keyed bundle of encrypted wallets across the requested chains. */
export async function generateWalletBundle(input: GenerateWalletBundleInput): Promise<GeneratedWalletBundle> {
  const bundle: GeneratedWalletBundle = {};
  if (input.solana?.length) {
    const wallets: ChainWallets = {};
    for (const role of input.solana) wallets[role] = await generateSolanaWallet(role, input.appKey);
    bundle.solana = wallets;
  }
  if (input.evm?.length) {
    const wallets: ChainWallets = {};
    for (const role of input.evm) wallets[role] = await generateEvmWallet(role, input.appKey);
    bundle.evm = wallets;
  }
  return bundle;
}

/** Flatten a bundle to the array stored server-side (public keys + ciphertext only). */
export function flattenBundle(bundle: GeneratedWalletBundle): EncryptedWallet[] {
  const out: EncryptedWallet[] = [];
  for (const chain of ["solana", "evm"] as Chain[]) {
    const wallets = bundle[chain];
    if (wallets) out.push(...Object.values(wallets));
  }
  return out;
}

/** Decrypt a wallet's secret. For Solana: 64-byte secret hex. For EVM: 0x private key. */
export async function decryptWalletSecret(wallet: EncryptedWallet, appKey: string): Promise<string> {
  return decryptSecret(wallet.encryptedSecret, appKey);
}

/** Reconstruct a Solana Keypair from an encrypted wallet. */
export async function toSolanaKeypair(wallet: EncryptedWallet, appKey: string): Promise<Keypair> {
  return Keypair.fromSecretKey(hexToBytes(await decryptWalletSecret(wallet, appKey)));
}

/**
 * Decrypt-to-sign: decrypt only for the duration of `fn`, then drop the reference.
 * (JS strings can't be truly zeroed; minimize lifetime and avoid persisting them.)
 */
export async function withDecryptedKey<T>(
  wallet: EncryptedWallet,
  appKey: string,
  fn: (secret: string) => Promise<T> | T,
): Promise<T> {
  let secret: string | null = await decryptWalletSecret(wallet, appKey);
  try {
    return await fn(secret);
  } finally {
    secret = null; // release reference ASAP
  }
}
