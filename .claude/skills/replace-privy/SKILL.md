---
name: replace-privy
description: Migrate a Next.js / React app from `@privy-io/react-auth` to `@tetrac/login-sdk` — replaces the custodial embedded-wallet stack (PrivyProvider, usePrivy, useWallets, useExportWallet) with the non-custodial, client-side-encrypted equivalents (AuthProvider, useAuth, useSigner, generateWalletBundle). Use when the user says "replace Privy", "swap out Privy", "remove @privy-io", "migrate off Privy", or asks how to drop Privy in favor of this SDK.
---

# Replacing Privy with `@tetrac/login-sdk`

## When to invoke

The user wants to remove `@privy-io/react-auth` (and `@privy-io/react-auth/solana`) from a Next.js / React app and replace it with `@tetrac/login-sdk`. Typical surface in a Privy-based app:

- An app-wide `<PrivyProvider appId="..." config={...}>` at the layout root.
- A `usePrivyWallet.ts` (or similar) compat shim that re-exports a `useWallet()` mimicking `@solana/wallet-adapter-react` on top of Privy.
- An `/export-key` page or "Export Private Key" button using `useExportWallet({ address })`.
- Embedded-wallet probing via `user.linkedAccounts.find(a => a.type === 'wallet' && a.walletClientType === 'privy')`.

The reference migration target in this skill set is `/Users/mac/Documents/Shyft.lol` — every example below has a sibling file there.

## The conceptual shift (read this before touching code)

Privy and `@tetrac/login-sdk` solve the same surface problem (let users log in and end up with a usable Solana/EVM wallet) with **opposite trust models**. Get this difference right and the migration is mechanical; get it wrong and you'll spend a day debugging why your wallets behave differently than Privy's did.

| | Privy embedded wallets | `@tetrac/login-sdk` |
|---|---|---|
| Key generation | Server-side MPC (Privy's infra) | Client-side in the browser (`Keypair.generate()`, viem `generatePrivateKey()`) |
| Key custody | Privy holds shares | Nobody — user's browser has the only decryptable copy |
| Server sees | MPC shares, OAuth identities | Ciphertext blob + public key. Not even the session token: the store holds only `SHA-256(token)` |
| Reveal / export | Privy hosts a reveal iframe (`exportWallet`) | App decrypts the local blob and renders it (`decryptWalletSecret` / `withDecryptedKey`) |
| Login methods | Email OTP, Google, Twitter, GitHub, external wallet | Email + passkey, Web3 wallet signature, biometric (WebAuthn PRF **required**). **No OAuth.** |
| Cross-device recovery | Privy reconstructs from MPC shares + login proof | Deterministic re-derivation of the encryption key from passkey+email or wallet signature |
| Storage | Privy's infra — nothing for you to run | **You run it.** Postgres/Supabase, MySQL, SQLite, and Redis/Upstash all ship first-party (§ Step 0.3) |

### Current version: 0.7.0

This skill targets **0.7.0**. Everything under `@tetrac/login-sdk/react` —
`AuthProvider`, `useAuth`, `useSigner`, `useUser`, `useExportKey`, `authHeaders()`,
`AuthResult.authToken` — works as written below.

Four things that shape the migration:

- **Storage is a real decision, and SQL is first-party now.** Postgres/Supabase, MySQL, and SQLite
  ship as `@tetrac/login-sdk/storage/sql`; Redis-family stays on `{ storage }`. Step 0.3.
- **`config.origin` is REQUIRED and permanent.** `resolveConfig` throws without it. It is app-key
  derivation input for Web3 accounts, exactly like `appId` — set it once, never change it. Step 1.
- **Session tokens are stored as `SHA-256` digests**, never in the clear. The client still receives
  and sends the raw token exactly as before, but a leaked server database yields *digests*, not
  replayable credentials. Worth raising if the user is comparing security postures with Privy.
- **Biometric requires WebAuthn PRF and fails closed.** There is no fallback mode. Authenticators
  without PRF throw `PrfUnavailableError` at registration — catch it and offer email+passkey rather
  than silently downgrading. Touch ID and Face ID have PRF; some older cross-platform keys do not.

> Already on an older SDK version rather than on Privy? Use the **`nextjs-login-sdk`** skill instead
> — upgrading 0.5.0 → 0.7.0 has two data-destroying steps that this skill does not cover.

Two practical consequences you MUST surface to the user before starting:

1. **OAuth is a gap.** If the existing Privy config has `loginMethods: ["email", "google", "twitter", "github", "wallet"]`, the SDK can replace email and wallet but not Google/Twitter/GitHub. Ask the user whether to drop those methods, gate them behind a "coming soon", or wrap a separate OAuth provider (NextAuth) and feed its account ID into the SDK as the email identifier. Do not silently delete OAuth login buttons.
2. **The export UX changes ownership.** With Privy, "Export key" pops Privy's hosted modal — your app never touches the plaintext. With the SDK, *your code* decrypts and displays it. You're responsible for the reveal UI, clipboard timeouts, and (critically) not logging the plaintext. Use `withDecryptedKey` to bound its lifetime.

## API mapping cheatsheet

| Privy | `@tetrac/login-sdk` |
|---|---|
| `<PrivyProvider appId config>` | `<AuthProvider apiBaseUrl config>` (from `@tetrac/login-sdk/react`) |
| `usePrivy() → { ready, authenticated, user, login, logout }` | `useAuth() → { status, isAuthenticated, publicKey, email, logout, registerWithEmail, loginWithEmail, connectWallet, registerWithBiometric, ... }` |
| `useWallets()` (Solana subpath) | `useAuth().publicKey` + `user.wallets` from `/api/auth/user-data` |
| `useExportWallet({ address })` | `useExportKey(walletBlob).reveal(reauth)` — enforces a fresh re-auth ceremony (preferred); low-level: `useSigner().decrypt(walletBlob)` |
| `embeddedWallets.solana.createOnLogin: "users-without-wallets"` | Automatic — `registerWithEmail` / `registerWithBiometric` / `connectWallet` generate the bundle |
| `user.linkedAccounts.find(a => a.walletClientType === 'privy')` | **`useActiveWallet()`** — do **not** hand-roll `wallets.find(w => w.role === "funds")` (see the ⚠️ below) |
| `solanaWallet.signTransaction({ transaction: bytes })` | Build a `Keypair` via `useSigner().solanaKeypair(walletBlob)`, then `tx.partialSign(kp)` |
| Privy's hosted UI / `appearance: {...}` | Build your own login UI; SDK is headless |

Server-side: Privy talks to Privy's API. The SDK requires you to run its routes **and its storage** yourself — `createNextAuthRoutes({ storage })` (Redis-family) or `createNextAuthRoutes({ store })` (SQL / custom) at `app/api/auth/[...action]/route.ts`. Step 0.3.

> **Use the ready-made React hooks.** This skill predates several first-class hooks the SDK now ships from `@tetrac/login-sdk/react`: `useUser` / `useWallets` / `useActiveWallet` (load the user record + encrypted wallets — no hand-rolled fetch), `useSolanaSigner` / `useEvmSigner` (drop-in `@solana/wallet-adapter`-shaped signers), `useExportKey` (reveal a key behind a forced re-auth ceremony), and `useBiometricUnlock` (add Touch/Face-ID unlock to *any* account). The hand-written shims below still work and are useful when you need exact wallet-adapter API compatibility, but prefer the official hooks where you can — they track the SDK's security model (memory-only vault, auto-lock, re-auth-to-reveal) for you.

## Migration plan (file by file)

Run these in order. Each step is self-contained — verify before moving on.

### Step 0 — Pre-flight

1. Confirm the user wants the OAuth methods dropped (or arrange a NextAuth bridge). Do this first; it shapes the rest of the work.
2. Decide where the server routes live. Default is `app/api/auth/[...action]/route.ts`. The SDK serves every endpoint from that one catch-all.
3. **Pick a storage backend.** Privy gave you this for free; now you run it. This is usually the only piece of *new infrastructure* the migration introduces, so raise it early rather than at deploy time.

   | Option | Wire it with | When |
   |---|---|---|
   | **Postgres / Supabase / Neon / RDS** | `createPostgresAuthStore({ client: pool })` | You already run Postgres. One wire protocol covers Supabase, Neon, RDS/Aurora, Railway, Render, Fly, CockroachDB. |
   | **MySQL / MariaDB** | `createMysqlAuthStore({ client })` | You already run MySQL. |
   | **SQLite / libSQL / Turso** | `createSqliteAuthStore({ client })` | Single-node or edge-replicated. |
   | **Upstash Redis** | `{ storage }` | No existing database. One env var, works on the edge runtime. |
   | **ioredis** (`REDIS_URL`) | `{ storage }` | Local dev, or self-hosted/managed Redis. Node runtime only. |
   | **Vercel KV** | `{ storage }` | **Legacy.** Vercel sunset it in Oct 2024 and routes it to Upstash now. Works, but don't pick it for a new deployment. |
   | **Mongo / DynamoDB / Convex** | hand-written `AuthStore` | Nothing ships. Use the **`multi-database`** skill — this is real work with real failure modes. |

   > **"I already run Postgres/Supabase — do I really need Redis?"** **No.** This used to be the
   > answer's weak point; it isn't any more. Postgres, MySQL, and SQLite are first-party:
   >
   > ```ts
   > import { createPostgresAuthStore, schemaFor } from "@tetrac/login-sdk/storage/sql";
   >
   > // 1. Run schemaFor("postgres") against your database — do NOT hand-write the schema.
   > // 2. Point the SDK at it. Preflight runs here and REFUSES TO BOOT on the dangerous stuff.
   > const store = await createPostgresAuthStore({ client: pool });
   > export const { GET, POST } = createNextAuthRoutes({ store, config: { origin, appId } });
   > ```
   >
   > The preflight is the reason to use this rather than hand-rolling: it refuses to boot on a
   > world-readable Supabase `public` schema, a non-strict MySQL that would silently truncate wallet
   > ciphertext, or a SQLite file sitting under a web-served directory. Those are exactly the
   > failures that don't show up in a smoke test.
   >
   > **Recommendation:** use the database you already have. Reach for Upstash only if you have none —
   > it is one env var and zero new infrastructure. Swapping later is a one-line change at the route,
   > with no client impact. **Do not hand-write an `AuthStore` for a SQL engine** — you would be
   > re-deriving correctness rules that already ship, tested against real engines.

4. Install:
   ```bash
   npm i @tetrac/login-sdk @solana/web3.js viem tweetnacl
   npm i @upstash/redis     # recommended; or `ioredis` for local/self-hosted Redis
   npm uninstall @privy-io/react-auth
   ```
   Leave `@solana/wallet-adapter-*` installed — you still need it for external-wallet detection (Phantom/Solflare/Backpack), which the SDK doesn't replace.

### Step 1 — Server route (new file)

Create `app/api/auth/[...action]/route.ts`:

```ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

// Picks Upstash / Vercel KV / ioredis from the environment. In production with NO
// backend configured it THROWS rather than falling back to a localhost Redis — that
// fallback would give every serverless instance its own ephemeral store (sessions that
// neither persist nor are shared). If this throws on deploy, your env vars aren't wired.
const storage = await resolveStorageAdapter();

export const { GET, POST } = createNextAuthRoutes({
  storage,
  config: {
    // BOTH of these are app-key derivation input and BOTH are permanent. Set them once.
    // Changing either re-derives every app key and existing wallets stop decrypting.
    appId: "shyft.lol",              // unique + stable; also the storage namespace.
                                     // The default "ttc" gives no isolation at all.
    origin: "https://shyft.lol",     // REQUIRED — resolveConfig throws without it.
                                     // Scheme + host (+ port). No path, no trailing slash.

    allowedAppIds: ["shyft.lol"],    // reject any other appId. Warns at boot if unset.
    webauthn: { rpName: "Shyft" },   // preferPrf is gone — PRF is mandatory now.

    // Set ONLY if a proxy you operate is actually in front (Vercel, Cloudflare, your
    // ingress). On a directly-reachable app, x-forwarded-for is caller-supplied and
    // trusting it is worse than leaving this off.
    trustProxyHeaders: !!process.env.VERCEL,
    trustedProxyHops: 0,
  },
  onWarning: (w) => console.warn(`[auth] ${w.code}: ${w.message}`),
});

export const runtime = "nodejs"; // ioredis requires node; use "edge" with Upstash
```

Backing it with a SQL database instead (Step 0.3): swap `storage` for `store`.

```ts
const store = await createPostgresAuthStore({ client: pool });
export const { GET, POST } = createNextAuthRoutes({ store, config: { appId, origin } });
```

**`origin` and preview deployments.** A Vercel preview on `https://app-git-xyz.vercel.app` derives
*different* Web3 app keys than production, because the origin is baked into the message the wallet
signs. Either pin the production origin in every environment sharing a database, or treat preview
accounts as throwaway. Do not let this one surface after launch.

Smoke-test: `curl -X POST http://localhost:3000/api/auth/challenge -H 'content-type: application/json' -d '{"publicKey":"xxx"}'` should return `{ "challenge": "<hex>", "pbkdf2Iterations": 600000 }`.

Note that `/challenge` answers `200` for an **unknown** email too, with an unstored dummy challenge —
that is deliberate (it used to be an account-existence oracle). Don't build an "account exists" check
on it; use the `409` from `/register`.

### Step 2 — Replace `WalletProvider.tsx`

The Privy version (`src/contexts/WalletProvider.tsx` in Shyft.lol) wraps the app in `<PrivyProvider>` with extensive config — login methods, embedded wallet auto-create, branding, RPCs, external connectors.

Replace it with two layered providers:

- `<AuthProvider>` from the SDK for auth + embedded wallet generation.
- `<WalletAdapterProvider>` (kept from `@solana/wallet-adapter-react`) for *external* wallets (Phantom, Solflare, Backpack). Their `signMessage` then feeds `connectWallet` in the SDK.

```tsx
// src/contexts/WalletProvider.tsx
"use client";

import React, { useMemo } from "react";
import { AuthProvider } from "@tetrac/login-sdk/react";
import { ConnectionProvider, WalletProvider as SolanaWalletProvider } from "@solana/wallet-adapter-react";
import { PhantomWalletAdapter, SolflareWalletAdapter, BackpackWalletAdapter } from "@solana/wallet-adapter-wallets";

const RPC_URL = typeof window !== "undefined"
  ? `${window.location.origin}/api/rpc`
  : `https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY_PRIVATE}`;

export default function WalletProvider({ children }: { children: React.ReactNode }) {
  const externalWallets = useMemo(
    () => [new PhantomWalletAdapter(), new SolflareWalletAdapter(), new BackpackWalletAdapter()],
    []
  );

  return (
    <ConnectionProvider endpoint={RPC_URL}>
      <SolanaWalletProvider wallets={externalWallets} autoConnect>
        <AuthProvider
          apiBaseUrl="/api/auth"
          walletGen={{ solana: ["funds", "signing"], evm: ["funds"] }}
          config={{ webauthn: { rpName: "Shyft" } }}
        >
          {children}
        </AuthProvider>
      </SolanaWalletProvider>
    </ConnectionProvider>
  );
}
```

Notes:
- The Privy `solana.rpcs` config (proxied Helius URL) moves onto `ConnectionProvider`.
- The Privy `embeddedWallets.solana.createOnLogin: "users-without-wallets"` behavior is now automatic inside the SDK — every `registerWithEmail`, `registerWithBiometric`, `connectWallet` generates a fresh bundle and stores it server-side as ciphertext.
- The Privy `appearance` block (logo, theme, login message) has no equivalent — you render your own modal/buttons.
- If the user kept EVM (Privy had `supportedChains: [base]`), include `evm: ["funds"]` in `walletGen`. Drop entirely if Solana-only.

### Step 3 — Rewrite the compat hook (`usePrivyWallet.ts`)

The existing shim presents a `useWallet()` matching `@solana/wallet-adapter-react`, layered over `usePrivy()` + Privy's `useWallets()`. Rename it to `useAuthWallet.ts` (or keep the filename if many files import it — saves a sweep) and reimplement:

```tsx
// src/hooks/useAuthWallet.ts  (was usePrivyWallet.ts)
"use client";

import { useEffect, useMemo, useState } from "react";
import { useAuth, useSigner } from "@tetrac/login-sdk/react";
import { authHeaders } from "@tetrac/login-sdk/client";
import { useWallet as useExternalWallet } from "@solana/wallet-adapter-react";
import { Connection, PublicKey, Transaction, VersionedTransaction, Keypair } from "@solana/web3.js";
import type { EncryptedWallet, UserData } from "@tetrac/login-sdk/core";

const RPC_PROXY = typeof window !== "undefined"
  ? `${window.location.origin}/api/rpc`
  : `https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY_PRIVATE}`;
export const HELIUS_MAINNET_RPC = RPC_PROXY;

let _sharedConnection: Connection | null = null;
export function getSharedConnection(): Connection {
  if (!_sharedConnection) {
    _sharedConnection = new Connection(HELIUS_MAINNET_RPC, {
      commitment: "confirmed",
      wsEndpoint: undefined,
      disableRetryOnRateLimit: false,
    });
  }
  return _sharedConnection;
}

/** Fetch the full UserData (incl. encrypted wallets) for the active session. */
function useUserData(): UserData | null {
  const { isAuthenticated, publicKey } = useAuth();
  const [user, setUser] = useState<UserData | null>(null);
  useEffect(() => {
    if (!isAuthenticated || !publicKey) { setUser(null); return; }
    fetch("/api/auth/user-data", { headers: authHeaders() })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setUser(data?.user ?? null))
      .catch(() => setUser(null));
  }, [isAuthenticated, publicKey]);
  return user;
}

export function useWallet() {
  const { isAuthenticated, publicKey: pubKeyStr, email, logout, connectWallet } = useAuth();
  const signer = useSigner();
  const external = useExternalWallet();             // Phantom / Solflare / Backpack
  const userData = useUserData();

  // Embedded Solana funds wallet (the user's primary on-chain identity).
  const embeddedFunds = useMemo<EncryptedWallet | undefined>(
    () => userData?.wallets.find((w) => w.chain === "solana" && w.role === "funds"),
    [userData]
  );

  // Active public key: external wallet beats embedded when an external is connected
  // (matches Privy's "first wallet wins" behavior in useWallets()).
  const publicKey = useMemo<PublicKey | null>(() => {
    if (external.publicKey) return external.publicKey;
    if (pubKeyStr) {
      try { return new PublicKey(pubKeyStr); } catch { return null; }
    }
    return null;
  }, [external.publicKey, pubKeyStr]);

  const connected = !!publicKey && (isAuthenticated || external.connected);
  const usingEmbedded = !external.connected && !!embeddedFunds;

  const signTransaction = useMemo(() => {
    return async <T extends Transaction | VersionedTransaction>(tx: T): Promise<T> => {
      if (external.signTransaction) return external.signTransaction(tx);
      if (!embeddedFunds) throw new Error("No wallet available to sign");
      // Decrypt → sign → drop the secret. Tight lifetime.
      return signer.sign(embeddedFunds, () => {
        const kp = signer.solanaKeypair(embeddedFunds);
        if (tx instanceof Transaction) tx.partialSign(kp);
        else tx.sign([kp]);
        return tx;
      });
    };
  }, [external.signTransaction, embeddedFunds, signer]);

  const signAllTransactions = useMemo(() => {
    return async <T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]> => {
      if (external.signAllTransactions) return external.signAllTransactions(txs);
      if (!embeddedFunds) throw new Error("No wallet available to sign");
      // One decrypt for the whole batch — same as Privy's batch behavior.
      return signer.sign(embeddedFunds, () => {
        const kp = signer.solanaKeypair(embeddedFunds);
        for (const tx of txs) {
          if (tx instanceof Transaction) tx.partialSign(kp);
          else tx.sign([kp]);
        }
        return txs;
      });
    };
  }, [external.signAllTransactions, embeddedFunds, signer]);

  // `login` opens your auth modal in the consuming app. Replace with a real call.
  const login = () => {
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("auth:open-modal"));
    }
  };

  return {
    publicKey,
    connected,
    signTransaction,
    signAllTransactions,
    wallet: embeddedFunds ?? external.wallet,
    evmWallet: userData?.wallets.find((w) => w.chain === "evm" && w.role === "funds"),
    evmAddress: userData?.wallets.find((w) => w.chain === "evm" && w.role === "funds")?.publicKey ?? null,
    isEmbeddedWallet: usingEmbedded,
    walletClientName: usingEmbedded ? "Shyft Embedded" : external.wallet?.adapter.name ?? "External",
    login,
    logout,
    ready: true,                 // SDK is synchronously ready after hydration
    authenticated: isAuthenticated,
    user: userData,
    connectWallet,               // exposed for the wallet-only login button
  };
}

export function useConnection() {
  const connection = useMemo(() => getSharedConnection(), []);
  return { connection };
}

export function useAnchorWallet() {
  const { publicKey, signTransaction, signAllTransactions } = useWallet();
  return useMemo(() => {
    if (!publicKey || !signTransaction || !signAllTransactions) return null;
    return { publicKey, signTransaction, signAllTransactions };
  }, [publicKey, signTransaction, signAllTransactions]);
}
```

Why this shape works:
- Existing call-sites that destructure `{ publicKey, connected, signTransaction, login, logout }` keep working.
- `signTransaction` transparently routes external-wallet calls to the adapter and embedded-wallet calls through `withDecryptedKey` — caller doesn't care which.
- `useAnchorWallet` keeps Anchor-based code (`useProgram`, etc.) unchanged.
- `login` is a custom event because the SDK is headless. The Landing component (or wherever the "Sign In" button lives) becomes responsible for opening the modal.

Update the import paths in every consumer file:
```bash
grep -rln "@/hooks/usePrivyWallet" src | xargs sed -i '' 's|@/hooks/usePrivyWallet|@/hooks/useAuthWallet|g'
```

### Step 4 — Build the login modal

Privy gave you a hosted modal for free. With the SDK you write it. Minimum viable version (drop into `src/components/AuthModal.tsx`):

```tsx
"use client";
import { useEffect, useState } from "react";
import { useAuth } from "@tetrac/login-sdk/react";
import { isBiometricAvailable, PrfUnavailableError, type PasskeyRegistration } from "@tetrac/login-sdk/client";
import { useWallet as useExternalWallet } from "@solana/wallet-adapter-react";

export function AuthModal() {
  const { registerWithEmail, loginWithEmail, connectWallet, registerWithBiometric, loginWithBiometric } = useAuth();
  const external = useExternalWallet();
  const [open, setOpen] = useState(false);
  const [bioAvailable, setBioAvailable] = useState(false);
  const [email, setEmail] = useState("");
  const [passkey, setPasskey] = useState("");

  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener("auth:open-modal", onOpen);
    isBiometricAvailable().then(setBioAvailable);
    return () => window.removeEventListener("auth:open-modal", onOpen);
  }, []);

  if (!open) return null;

  const onEmail = async () => {
    try { await registerWithEmail({ email, passkey }); }
    catch (e: any) {
      if (String(e).includes("already exists")) await loginWithEmail({ email, passkey });
      else throw e;
    }
    setOpen(false);
  };

  const onWallet = async () => {
    if (!external.publicKey || !external.signMessage) return;
    await connectWallet({
      publicKey: external.publicKey.toBase58(),
      signMessage: external.signMessage,
    });
    setOpen(false);
  };

  const onBiometric = async () => {
    try {
      const stored = localStorage.getItem("ttc-passkey-reg");
      if (stored) {
        await loginWithBiometric({ registration: JSON.parse(stored) as PasskeyRegistration });
      } else {
        const { registration } = await registerWithBiometric({ userName: email || "Shyft user" });
        localStorage.setItem("ttc-passkey-reg", JSON.stringify(registration));
      }
      setOpen(false);
    } catch (e) {
      // The authenticator has no WebAuthn PRF, so there is no assertion-bound secret to
      // derive the app key from. The SDK fails closed here on purpose — the old fallback
      // stored a secret any same-origin script could decrypt without any biometric prompt.
      // Route the user to email+passkey; do NOT retry or downgrade.
      if (e instanceof PrfUnavailableError) setBioAvailable(false);
      else throw e;
    }
  };

  return (
    <div /* your modal styling */>
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
      <input type="password" value={passkey} onChange={(e) => setPasskey(e.target.value)} placeholder="passkey" />
      <button onClick={onEmail}>Continue with email</button>
      <button onClick={onWallet} disabled={!external.connected}>Continue with wallet</button>
      {bioAvailable && <button onClick={onBiometric}>Continue with Touch ID</button>}
    </div>
  );
}
```

Mount it once near the root (inside `<AuthProvider>`). The Privy hosted modal's branding (`appearance.logo`, `loginMessage`) becomes your responsibility — match what the user expects.

### Step 5 — Rewrite the export-key flow

The two Privy export sites in Shyft.lol are `src/app/export-key/page.tsx` (React Native WebView shell) and the Export Key button in `src/components/Profile.tsx`. Both call `useExportWallet().exportWallet({ address })`, which pops Privy's hosted reveal iframe.

Replace with a **local reveal** — your code decrypts the embedded wallet's secret and shows it in your own UI.

**Preferred: `useExportKey`.** The SDK ships a reveal hook that mirrors Privy's "re-auth before reveal" behavior: `reveal(reauth)` runs a **fresh re-authentication ceremony every time**, derives a one-time key, never reads the ambient (possibly-unlocked) session key, and auto-clears the plaintext after 30s. Pass the creds for the account's auth method — `{ passkey }` (email), `{ signMessage }` (web3), or `{ registration }` / `{ biometricUnlock }` (biometric).

```tsx
// src/app/export-key/page.tsx  (preferred — forced re-auth)
"use client";
import { useState } from "react";
import { useAuth, useUser, useExportKey } from "@tetrac/login-sdk/react";

export default function ExportKeyPage() {
  const { isAuthenticated, status } = useAuth();
  const { user } = useUser();                       // loaded record, no hand-rolled fetch
  const solanaFunds = user?.wallets.find((w) => w.chain === "solana" && w.role === "funds");
  const { reveal, plaintext, error, clear } = useExportKey(solanaFunds); // auto-clears after 30s
  const [passkey, setPasskey] = useState("");

  if (!isAuthenticated) return <p>Sign in first. (status: {status})</p>;

  const onReveal = async () => {
    try {
      const secret = await reveal({ passkey });     // fresh ceremony; { signMessage } / { registration } for web3 / biometric
      (window as any).ReactNativeWebView?.postMessage(JSON.stringify({ status: "success", privateKey: secret }));
    } catch (err: any) {
      (window as any).ReactNativeWebView?.postMessage(JSON.stringify({ status: "error", error: err?.message ?? "Export failed" }));
    }
  };

  return (
    <div>
      <h1>Export Private Key</h1>
      {error && <p>{error.message}</p>}
      {!plaintext ? (
        <>
          <input type="password" value={passkey} onChange={(e) => setPasskey(e.target.value)} placeholder="re-enter passkey" />
          <button onClick={onReveal}>Reveal private key</button>
        </>
      ) : (
        <>
          <code style={{ wordBreak: "break-all" }}>{plaintext}</code>
          <button onClick={() => { navigator.clipboard.writeText(plaintext); setTimeout(() => navigator.clipboard.writeText(""), 30_000); }}>Copy</button>
          <button onClick={clear}>Hide</button>
        </>
      )}
    </div>
  );
}
```

**Lower-level alternative.** If you need to drive the decrypt yourself (custom state, the RN-WebView shell wiring below), `useSigner().sign(wallet, secret => secret)` works — but note it reads the **ambient unlocked vault key** and does NOT force a re-auth, so prefer `useExportKey`/`client.revealSecret(wallet, reauth)` whenever you want Privy-equivalent reveal friction:

```tsx
// src/app/export-key/page.tsx  (lower-level — uses the ambient session key, no forced re-auth)
"use client";

import { useEffect, useState } from "react";
import { useAuth, useSigner } from "@tetrac/login-sdk/react";
import { authHeaders } from "@tetrac/login-sdk/client";
import type { UserData, EncryptedWallet } from "@tetrac/login-sdk/core";

export default function ExportKeyPage() {
  const { isAuthenticated, status } = useAuth();
  const { unlocked, sign } = useSigner();
  const [user, setUser] = useState<UserData | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetch("/api/auth/user-data", { headers: authHeaders() })
      .then((r) => r.json())
      .then((d) => setUser(d.user))
      .catch((e) => setError(String(e)));
  }, [isAuthenticated]);

  // Auto-clear after 60 s so a screenshot/screenshare window doesn't linger.
  useEffect(() => {
    if (!revealed) return;
    const t = setTimeout(() => setRevealed(null), 60_000);
    return () => clearTimeout(t);
  }, [revealed]);

  const solanaFunds = user?.wallets.find((w) => w.chain === "solana" && w.role === "funds");

  async function handleExport() {
    if (!solanaFunds) {
      setError("No embedded Solana wallet found");
      return;
    }
    if (!unlocked) {
      setError("Session locked. Sign in again to decrypt.");
      return;
    }
    try {
      // withDecryptedKey bounds the plaintext lifetime — set state inside, then
      // the reference in `secret` is released as soon as the callback returns.
      const plaintext = await sign(solanaFunds, (secret) => secret);
      setRevealed(plaintext);
      // Mirror the Privy postMessage contract so the RN WebView shell still works.
      (window as any).ReactNativeWebView?.postMessage(
        JSON.stringify({ status: "success", privateKey: plaintext })
      );
    } catch (err: any) {
      setError(err?.message ?? "Export failed");
      (window as any).ReactNativeWebView?.postMessage(
        JSON.stringify({ status: "error", error: err?.message ?? "Export failed" })
      );
    }
  }

  if (!isAuthenticated) {
    return <p>Sign in first. (status: {status})</p>;
  }

  return (
    <div>
      <h1>Export Private Key</h1>
      {error && <p>{error}</p>}
      {!revealed ? (
        <button onClick={handleExport}>Reveal private key</button>
      ) : (
        <>
          <code style={{ wordBreak: "break-all" }}>{revealed}</code>
          <button
            onClick={() => {
              navigator.clipboard.writeText(revealed);
              setTimeout(() => navigator.clipboard.writeText(""), 30_000);
            }}
          >Copy</button>
          <button onClick={() => setRevealed(null)}>Hide</button>
        </>
      )}
    </div>
  );
}
```

For `Profile.tsx` — the same logic, just inline. Replace the existing `useExportWallet` import + `handleExportWallet` body with `useExportKey(walletBlob).reveal(reauth)`. The `isEmbeddedWallet` / `walletClientName` props already come through the new `useAuthWallet` hook, so the surrounding UI doesn't change.

Key UX differences from Privy worth surfacing in your UI:
- Privy's reveal modal forces a re-auth ceremony. **`useExportKey().reveal(reauth)` / `client.revealSecret(wallet, reauth)` give you the same friction by design** — they always re-run the ceremony and never use the ambient key. (The lower-level `useSigner().sign(...)` does NOT force re-auth; it operates on the in-memory vault key while it's unlocked.)
- The app/encryption key is **memory-only** — it is NOT in `sessionStorage` or `localStorage`. It auto-locks after ~15s idle and on tab hide / page freeze / bfcache restore, after which signer/decrypt calls throw `VaultLockedError` until the user re-authenticates. (Only the bearer token + public key live in `localStorage`.)
- Privy's iframe sandbox protected the plaintext from XSS. With the SDK, an XSS in your page can read the revealed plaintext while it's in state. Treat the reveal route as security-sensitive (strong CSP, no untrusted third-party scripts on that route).

### Step 6 — Sweep the remaining files

In Shyft.lol these are tiny:
- `src/components/Landing.tsx` — uses `useWallet().login`. Already covered by the compat shim — no edit needed beyond the import-path rewrite from Step 3.
- `src/lib/reserved-usernames.ts` — has the string `"privy"` in a reserved-username list. Leave alone (or remove if the brand association is gone).

Anything that imported `@privy-io/react-auth` directly needs to be either deleted or rewritten through `useAuth` / `useWallet`. Search:
```bash
grep -rln "@privy-io" src
```
After Step 5 this should return zero results.

### Step 7 — Tear down Privy

```bash
npm uninstall @privy-io/react-auth
```

Remove the Privy app ID from `.env.local` (`NEXT_PUBLIC_PRIVY_APP_ID` or similar). Remove any Privy branding (`/public/privy.jpg` if no longer in the partners section of Landing).

## Verification checklist

After the migration, walk through each one. Don't skip — Privy gave you a lot of behavior for free and easy to miss a regression.

- [ ] `grep -rln "@privy-io" src` returns nothing.
- [ ] **Storage is actually wired in the deployed environment.** `resolveStorageAdapter()` throws in production when no backend env var is set (rather than silently falling back to a localhost Redis that would give each instance its own ephemeral store). A successful deploy that 500s on first login is almost always this.
- [ ] **`config.appId` AND `config.origin` are set, unique, and stable.** Both are app-key derivation input — changing either later re-derives every app key and existing wallets stop decrypting. `origin` must be identical across every environment that shares a database (watch Vercel preview URLs).
- [ ] **Boot warnings are clean.** `createAuthHandlers` warns on `unrestricted_app_id` (set `allowedAppIds`), `default_app_id` (appId still `"ttc"`), and `no_requester_identity` (`trustProxyHeaders` false). Each names a real consequence — resolve or consciously accept.
- [ ] **Biometric registration handles `PrfUnavailableError`** rather than showing a generic failure. There is no fallback mode.
- [ ] Email signup: new account → wallet generated → network tab shows the POST `/api/auth/register` body contains `wallets[].encryptedSecret` (ciphertext) but **no plaintext** secret/private key.
- [ ] Email login on a second device with same email+passkey → same wallet public key surfaces (deterministic recovery works).
- [ ] Wallet login (Phantom): two signature prompts (challenge + app-key message), then `connected` flips to true.
- [ ] Biometric login (if enabled): registration completes, persisted `PasskeyRegistration` works on subsequent visits.
- [ ] Anchor calls (`useProgram` etc.) still sign and submit successfully.
- [ ] Export key page: reveal shows the plaintext, postMessage to RN WebView fires, the value disappears after the auto-clear timeout.
- [ ] Logout clears the bearer token + public key from `localStorage` and drops the in-memory app key (the key is never in `sessionStorage`/`localStorage` to begin with).
- [ ] Closing the tab and reopening sets `status` to `session_expired` (token survives in localStorage but the memory-only appKey is gone) — re-login is required to spend.
- [ ] Leaving the tab idle ~15s (or switching tabs) auto-locks the vault: `useSigner().unlocked` flips to false and signing throws `VaultLockedError` until re-auth.
- [ ] **Importing a wallet REPLACES its `(chain, role)` slot** rather than appending. A record holds at most four wallets (`WALLET_SLOTS`). If any UI resolves a wallet with `.find()`, confirm it surfaces the replacement and not a stale earlier entry.
- [ ] Logging in on a second device **immediately invalidates the first**. Single active session is enforced on every request, not just at issuance — expect the older device to 401 rather than linger until TTL.

## Gotchas specific to this migration

**`signTransaction` argument shape.** Privy's `wallet.signTransaction({ transaction: bytes })` takes a `{transaction}` object and returns `{signedTransaction}`. The compat shim above hides that — call-sites just use the wallet-adapter shape (`signTransaction(tx) → tx`). If you find a site that was passing the Privy-shaped object directly, it needs to switch to passing the Transaction/VersionedTransaction.

**Embedded EVM wallet.** Privy auto-created an EVM wallet on Base. The SDK's `walletGen: { evm: ["funds"] }` does the same, but only on email/biometric registration. If a user signs in via `connectWallet` (Solana signature), they don't get an EVM wallet automatically because `connectWallet` registers them as `authMethod: "wallet"` and the EVM key would be encrypted under a key derived from the Solana signature — fine for them, but no Privy-equivalent EVM identity on external-wallet users. Decide if that matters for your app.

**`user.linkedAccounts` is gone — and don't replace it with `role === "funds"`. ⚠️** Use
**`useActiveWallet()`** (or `useWallets().find(w => w.isIdentity)`).

`role === "funds"` looks like the obvious translation and it is **wrong for Web3 accounts**. For an
email/biometric account the embedded Solana `funds` wallet *is* the identity. For a
`authMethod: "wallet"` account the identity is the **connected wallet** (`user.publicKey`) — the SDK
holds no key for it, and it is *not* in `user.wallets`. So:

- `wallets.find(w => w.role === "funds")` returns **nothing** for a clean Web3 account…
- …or, on an account created by an old SDK version, it returns a **stray embedded wallet** that
  should never have been generated. Render that as a deposit address and the user sends funds to a
  wallet they don't know they own. (`connectWallet`/`registerWithWallet` no longer mint a second
  Solana funds wallet, and `useActiveWallet()` resolves the Web3 identity from the record rather than
  from the wallet-adapter connection.)

`useActiveWallet()` gets this right on both paths, and returns `encrypted: null` for an external
wallet — which is also your signal that there is **nothing to export** (you cannot export a Phantom
key). Gate any export UI on `active?.encrypted`, exactly as the demo does.

**`embeddedWallets.showWalletUIs: false`** — no equivalent needed; the SDK has no UI to hide.

**Privy's `ready` flag** — the SDK is synchronously ready after the React tree hydrates. The compat shim returns `ready: true` unconditionally; if you had spinners gated on `ready`, they'll resolve immediately. Don't add fake delays — fix the gated UI to not block on it.

**RPC URL collision.** Privy held the Solana RPC inside its provider config. After migration the RPC moves to `<ConnectionProvider endpoint>`. If `useConnection()` from the shim and `useConnection()` from `@solana/wallet-adapter-react` are both imported in different files, they'll return different `Connection` instances. Standardize on one — the shim's `getSharedConnection()` is the simpler option for non-React contexts.

## What this skill does not cover

- **OAuth methods (Google, Twitter, GitHub).** Not supported. If the user needs them, either drop those buttons, or bridge via NextAuth: have NextAuth complete the OAuth flow, then call `registerWithEmail({ email: oauthEmail, passkey: deterministic-from-oauth-sub })`. That bridge is its own design exercise — don't improvise it inside this migration.
- **Privy Smart Wallets / Account Abstraction.** Not supported. If the Privy app relied on 4337 smart accounts, this SDK can't drop in — flag and stop.
- **Migrating an *already-active* Privy user base.** Existing users have keys held by Privy's MPC. There is no way to import those into a non-custodial scheme without first calling Privy's `exportWallet` on each user and asking them to import the raw key into the new SDK. Treat this as a separate UX project; this skill assumes a fresh deployment or a deliberate keep-existing-Privy-users-on-Privy phase.
- **Writing a custom `AuthStore`** for an engine that doesn't ship (Mongo, DynamoDB, Convex, Durable Objects). Postgres/MySQL/SQLite/Redis all ship — do **not** hand-write those. For anything else, use the **`multi-database`** skill, verify against `@tetrac/login-sdk/storage/conformance`, and do it as a **separate change** from the Privy migration. Don't improvise a database backend and a wallet-stack swap in the same PR.
- **Upgrading an app already on an older `@tetrac/login-sdk`.** That is the **`nextjs-login-sdk`** skill, and it has two data-destroying steps this one doesn't cover.
