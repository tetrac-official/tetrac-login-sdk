---
name: replace-privy
description: Migrate a Next.js / React app from `@privy-io/react-auth` to `@tetrac/login-sdk` — replaces the custodial embedded-wallet stack (PrivyProvider, usePrivy, useWallets, useExportWallet) with the non-custodial, client-side-encrypted equivalents (AuthProvider, useAuth, useWallet, generateWalletBundle). Use when the user says "replace Privy", "swap out Privy", "remove @privy-io", "migrate off Privy", or asks how to drop Privy in favor of this SDK.
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
| Server sees | MPC shares, OAuth identities | Ciphertext blob + public key only |
| Reveal / export | Privy hosts a reveal iframe (`exportWallet`) | App decrypts the local blob and renders it (`decryptWalletSecret` / `withDecryptedKey`) |
| Login methods | Email OTP, Google, Twitter, GitHub, external wallet | Email + passkey, Web3 wallet signature, biometric (WebAuthn PRF). **No OAuth.** |
| Cross-device recovery | Privy reconstructs from MPC shares + login proof | Deterministic re-derivation of the encryption key from passkey+email or wallet signature |

Two practical consequences you MUST surface to the user before starting:

1. **OAuth is a gap.** If the existing Privy config has `loginMethods: ["email", "google", "twitter", "github", "wallet"]`, the SDK can replace email and wallet but not Google/Twitter/GitHub. Ask the user whether to drop those methods, gate them behind a "coming soon", or wrap a separate OAuth provider (NextAuth) and feed its account ID into the SDK as the email identifier. Do not silently delete OAuth login buttons.
2. **The export UX changes ownership.** With Privy, "Export key" pops Privy's hosted modal — your app never touches the plaintext. With the SDK, *your code* decrypts and displays it. You're responsible for the reveal UI, clipboard timeouts, and (critically) not logging the plaintext. Use `withDecryptedKey` to bound its lifetime.

## API mapping cheatsheet

| Privy | `@tetrac/login-sdk` |
|---|---|
| `<PrivyProvider appId config>` | `<AuthProvider apiBaseUrl config>` (from `@tetrac/login-sdk/react`) |
| `usePrivy() → { ready, authenticated, user, login, logout }` | `useAuth() → { status, isAuthenticated, publicKey, email, logout, registerWithEmail, loginWithEmail, connectWallet, registerWithBiometric, ... }` |
| `useWallets()` (Solana subpath) | `useAuth().publicKey` + `user.wallets` from `/api/auth/user-data` |
| `useExportWallet({ address })` | `useWallet().decrypt(walletBlob)` or `withDecryptedKey(walletBlob, appKey, fn)` |
| `embeddedWallets.solana.createOnLogin: "users-without-wallets"` | Automatic — `registerWithEmail` / `registerWithBiometric` / `connectWallet` generate the bundle |
| `user.linkedAccounts.find(a => a.walletClientType === 'privy')` | `user.wallets.find(w => w.chain === "solana" && w.role === "funds")` |
| `solanaWallet.signTransaction({ transaction: bytes })` | Build a `Keypair` via `useWallet().solanaKeypair(walletBlob)`, then `tx.partialSign(kp)` |
| Privy's hosted UI / `appearance: {...}` | Build your own login UI; SDK is headless |

Server-side: Privy talks to Privy's API. The SDK requires you to run its routes yourself — `createNextAuthRoutes({ storage })` at `app/api/auth/[...action]/route.ts`. See `docs/USE_IN_CODE.md` §3.

## Migration plan (file by file)

Run these in order. Each step is self-contained — verify before moving on.

### Step 0 — Pre-flight

1. Confirm the user wants the OAuth methods dropped (or arrange a NextAuth bridge). Do this first; it shapes the rest of the work.
2. Decide where the server routes live. Default is `app/api/auth/[...action]/route.ts`. The SDK serves every endpoint from that one catch-all.
3. Pick a storage backend (Redis local / Upstash / Vercel KV) and add the env vars. See `docs/USE_IN_CODE.md` §2.
4. Install:
   ```bash
   npm i @tetrac/login-sdk @solana/web3.js viem tweetnacl
   npm i ioredis            # or @upstash/redis / @vercel/kv
   npm uninstall @privy-io/react-auth
   ```
   Leave `@solana/wallet-adapter-*` installed — you still need it for external-wallet detection (Phantom/Solflare/Backpack), which the SDK doesn't replace.

### Step 1 — Server route (new file)

Create `app/api/auth/[...action]/route.ts`:

```ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter();

export const { GET, POST } = createNextAuthRoutes({
  storage,
  config: {
    webauthn: { rpName: "Shyft", preferPrf: true },
    // sessionHeader / publicKeyHeader / keyPrefixes only if you need to namespace
  },
});

export const runtime = "nodejs"; // ioredis requires node; use "edge" with Upstash
```

Smoke-test: `curl -X POST http://localhost:3000/api/auth/challenge -H 'content-type: application/json' -d '{"publicKey":"xxx"}'` should return `{ "challenge": "<hex>" }`.

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
          config={{ webauthn: { rpName: "Shyft", preferPrf: true } }}
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
import { useAuth, useWallet as useSdkWallet } from "@tetrac/login-sdk/react";
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
  const sdkWallet = useSdkWallet();
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
      return sdkWallet.sign(embeddedFunds, () => {
        const kp = sdkWallet.solanaKeypair(embeddedFunds);
        if (tx instanceof Transaction) tx.partialSign(kp);
        else tx.sign([kp]);
        return tx;
      });
    };
  }, [external.signTransaction, embeddedFunds, sdkWallet]);

  const signAllTransactions = useMemo(() => {
    return async <T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]> => {
      if (external.signAllTransactions) return external.signAllTransactions(txs);
      if (!embeddedFunds) throw new Error("No wallet available to sign");
      // One decrypt for the whole batch — same as Privy's batch behavior.
      return sdkWallet.sign(embeddedFunds, () => {
        const kp = sdkWallet.solanaKeypair(embeddedFunds);
        for (const tx of txs) {
          if (tx instanceof Transaction) tx.partialSign(kp);
          else tx.sign([kp]);
        }
        return txs;
      });
    };
  }, [external.signAllTransactions, embeddedFunds, sdkWallet]);

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
import { isBiometricAvailable, type PasskeyRegistration } from "@tetrac/login-sdk/client";
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
    const stored = localStorage.getItem("ttc-passkey-reg");
    if (stored) {
      await loginWithBiometric({ registration: JSON.parse(stored) as PasskeyRegistration });
    } else {
      const { registration } = await registerWithBiometric({ userName: email || "Shyft user" });
      localStorage.setItem("ttc-passkey-reg", JSON.stringify(registration));
    }
    setOpen(false);
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

Replace with a **local reveal** — you decrypt the embedded wallet's encrypted secret and show it in your own UI. The plaintext lives on a `useState` for the duration of the reveal, then is cleared.

```tsx
// src/app/export-key/page.tsx
"use client";

import { useEffect, useState } from "react";
import { useAuth, useWallet } from "@tetrac/login-sdk/react";
import { authHeaders } from "@tetrac/login-sdk/client";
import type { UserData, EncryptedWallet } from "@tetrac/login-sdk/core";

export default function ExportKeyPage() {
  const { isAuthenticated, status } = useAuth();
  const { unlocked, sign } = useWallet();
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

For `Profile.tsx` — the same logic, just inline. Replace the existing `useExportWallet` import + `handleExportWallet` body with the `useWallet().sign(walletBlob, secret => secret)` pattern. The `isEmbeddedWallet` / `walletClientName` props already come through the new `useAuthWallet` hook, so the surrounding UI doesn't change.

Key UX differences from Privy worth surfacing in your UI:
- Privy's reveal modal forces a re-auth ceremony. The SDK's `useWallet().sign(...)` will succeed silently if the app key is hot in `sessionStorage`. For the reveal flow specifically, consider calling `logout()` + force re-auth first if you want the same friction.
- Privy's iframe sandbox protected the plaintext from XSS. With the SDK, an XSS in your page can read `revealed`. Treat the reveal route as security-sensitive (strong CSP, no untrusted third-party scripts on that route).

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
- [ ] Email signup: new account → wallet generated → network tab shows the POST `/api/auth/register` body contains `wallets[].encryptedSecret` (ciphertext) but **no plaintext** secret/private key.
- [ ] Email login on a second device with same email+passkey → same wallet public key surfaces (deterministic recovery works).
- [ ] Wallet login (Phantom): two signature prompts (challenge + app-key message), then `connected` flips to true.
- [ ] Biometric login (if enabled): registration completes, persisted `PasskeyRegistration` works on subsequent visits.
- [ ] Anchor calls (`useProgram` etc.) still sign and submit successfully.
- [ ] Export key page: reveal shows the plaintext, postMessage to RN WebView fires, the value disappears after the auto-clear timeout.
- [ ] Logout clears the session and the `ttc_ek` `sessionStorage` entry.
- [ ] Closing the tab and reopening sets `status` to `session_expired` (token survives in localStorage but appKey is gone) — re-login is required to spend.

## Gotchas specific to this migration

**`signTransaction` argument shape.** Privy's `wallet.signTransaction({ transaction: bytes })` takes a `{transaction}` object and returns `{signedTransaction}`. The compat shim above hides that — call-sites just use the wallet-adapter shape (`signTransaction(tx) → tx`). If you find a site that was passing the Privy-shaped object directly, it needs to switch to passing the Transaction/VersionedTransaction.

**Embedded EVM wallet.** Privy auto-created an EVM wallet on Base. The SDK's `walletGen: { evm: ["funds"] }` does the same, but only on email/biometric registration. If a user signs in via `connectWallet` (Solana signature), they don't get an EVM wallet automatically because `connectWallet` registers them as `authMethod: "wallet"` and the EVM key would be encrypted under a key derived from the Solana signature — fine for them, but no Privy-equivalent EVM identity on external-wallet users. Decide if that matters for your app.

**`user.linkedAccounts` is gone.** Anywhere code probed `user.linkedAccounts` to find embedded vs external, switch to `user.wallets.find((w) => w.chain === "solana" && w.role === "funds")` (embedded) vs `useExternalWallet().connected` (external).

**`embeddedWallets.showWalletUIs: false`** — no equivalent needed; the SDK has no UI to hide.

**Privy's `ready` flag** — the SDK is synchronously ready after the React tree hydrates. The compat shim returns `ready: true` unconditionally; if you had spinners gated on `ready`, they'll resolve immediately. Don't add fake delays — fix the gated UI to not block on it.

**RPC URL collision.** Privy held the Solana RPC inside its provider config. After migration the RPC moves to `<ConnectionProvider endpoint>`. If `useConnection()` from the shim and `useConnection()` from `@solana/wallet-adapter-react` are both imported in different files, they'll return different `Connection` instances. Standardize on one — the shim's `getSharedConnection()` is the simpler option for non-React contexts.

## What this skill does not cover

- **OAuth methods (Google, Twitter, GitHub).** PRD §14 marks them as open. If the user needs them, either drop those buttons, or bridge via NextAuth: have NextAuth complete the OAuth flow, then call `registerWithEmail({ email: oauthEmail, passkey: deterministic-from-oauth-sub })`. That bridge is its own design exercise — don't improvise it inside this migration.
- **Privy Smart Wallets / Account Abstraction.** Not in v1 (PRD §1, Non-Goals). If the Privy app relied on 4337 smart accounts, this SDK can't drop in — flag and stop.
- **Migrating an *already-active* Privy user base.** Existing users have keys held by Privy's MPC. There is no way to import those into a non-custodial scheme without first calling Privy's `exportWallet` on each user and asking them to import the raw key into the new SDK. Treat this as a separate UX project; this skill assumes a fresh deployment or a deliberate keep-existing-Privy-users-on-Privy phase.
