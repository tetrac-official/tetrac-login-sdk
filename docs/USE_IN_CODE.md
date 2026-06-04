# Using `@tetrac/login-sdk` in Code

Practical, copy-paste examples for integrating the SDK into Node.js backends and
Next.js (App Router) apps. For the product spec see [`PRD.md`](./PRD.md); for the
top-level overview see [`../README.md`](../README.md).

---

## Table of Contents

1. [Install](#1-install)
2. [Environment](#2-environment)
3. [Next.js App Router — Server routes](#3-nextjs-app-router--server-routes)
4. [Next.js App Router — React client](#4-nextjs-app-router--react-client)
5. [Vanilla browser client (no React)](#5-vanilla-browser-client-no-react)
6. [Plain Node.js backend (Express / Fastify / Hono)](#6-plain-nodejs-backend-express--fastify--hono)
7. [Verifying sessions in your own routes](#7-verifying-sessions-in-your-own-routes)
8. [Wallet generation & decrypt-to-sign](#8-wallet-generation--decrypt-to-sign)
9. [Custom storage adapter](#9-custom-storage-adapter)
10. [Configuration overrides](#10-configuration-overrides)
11. [Common patterns & gotchas](#11-common-patterns--gotchas)

---

## 1. Install

```bash
npm i @tetrac/login-sdk

# Peer deps (install what you use):
npm i @solana/web3.js viem tweetnacl

# Storage backend (pick one):
npm i ioredis            # local dev (redis://localhost:6379)
npm i @vercel/kv         # Vercel KV
npm i @upstash/redis     # Upstash REST (edge-friendly)

# React / Next bindings:
npm i react next
```

Subpath exports keep server-only code (storage drivers, route factories) out of
browser bundles — always import from the most specific subpath:

| Import | Environment | Purpose |
|---|---|---|
| `@tetrac/login-sdk/core` | both | types, config, crypto helpers |
| `@tetrac/login-sdk/client` | browser | wallet gen, sessions, WebAuthn, `AuthClient` |
| `@tetrac/login-sdk/server` | server | route factory, session verify, signature verify |
| `@tetrac/login-sdk/storage` | server | `StorageAdapter` + Redis/KV/Upstash adapters |
| `@tetrac/login-sdk/react` | browser | `AuthProvider`, `useAuth`, `useUser`, `useWallets`, `useActiveWallet`, `useSigner`, `useSolanaSigner`, `useEvmSigner` |
| `@tetrac/login-sdk/next` | server | `createNextAuthRoutes` |

---

## 2. Environment

```bash
# Dev — local Redis
REDIS_URL=redis://localhost:6379

# Production — pick one:
VERCEL=1                                   # auto-uses @vercel/kv
KV_REST_API_URL=...                        # Vercel KV REST
KV_REST_API_TOKEN=...
UPSTASH_REDIS_REST_URL=...                 # Upstash
UPSTASH_REDIS_REST_TOKEN=...
```

`resolveStorageAdapter()` picks one based on those vars in this order:
**Upstash → Vercel KV → ioredis**.

---

## 3. Next.js App Router — Server routes

Wire up a single catch-all route handler. The SDK serves every auth endpoint
under one file:

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter();

export const { GET, POST } = createNextAuthRoutes({ storage });

// Make sure this runs on Node (not edge) when using ioredis.
// Upstash REST works on the edge runtime too.
export const runtime = "nodejs";
```

That exposes:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/challenge` | Issue a 32-byte single-use challenge (5-min TTL) |
| `POST` | `/api/auth/register` | Create account, persist encrypted wallet bundle, issue session |
| `POST` | `/api/auth/login` | Email + passkey login |
| `POST` | `/api/auth/login-wallet` | Web3 wallet login (verifies tweetnacl signature) |
| `POST` | `/api/auth/connect-wallet` | Login-or-register a Web3 wallet in one round trip |
| `POST` | `/api/auth/import-wallet` | Import an external wallet into an existing account |
| `GET`  | `/api/auth/user-data` | Return UserData for the current session |
| `GET`  | `/api/auth/search-wallet?publicKey=...` | Existence check |

### With config overrides

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter();

export const { GET, POST } = createNextAuthRoutes({
  storage,
  config: {
    pbkdf2Iterations: 200_000,                 // stronger key derivation
    challengeTtlSeconds: 120,                  // tighter replay window
    rateLimit: { windowSeconds: 60, maxAttempts: 5 },
    webauthn: { rpName: "Acme", preferPrf: true },
    // sessionHeader / publicKeyHeader / keyPrefixes also overridable
  },
});

export const runtime = "nodejs";
```

> ⚠️ If you override `sessionHeader` / `publicKeyHeader` / `keyPrefixes` on the
> server, you must override them identically on the `AuthClient` /
> `AuthProvider` — they have to agree on header names and Redis key namespaces.

---

## 4. Next.js App Router — React client

### Wrap the app

```tsx
// app/layout.tsx
import { AuthProvider } from "@tetrac/login-sdk/react";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <AuthProvider apiBaseUrl="/api/auth">
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

`AuthProvider` is a client component — make sure the file it lives in (or a
parent client boundary) has `"use client"` if you import it directly into a
server component. The cleanest pattern is:

```tsx
// app/providers.tsx
"use client";
import { AuthProvider } from "@tetrac/login-sdk/react";

export function Providers({ children }: { children: React.ReactNode }) {
  return <AuthProvider apiBaseUrl="/api/auth">{children}</AuthProvider>;
}

// app/layout.tsx — server component
import { Providers } from "./providers";
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html><body><Providers>{children}</Providers></body></html>;
}
```

### Email + passkey

```tsx
// app/(auth)/EmailSignup.tsx
"use client";
import { useState } from "react";
import { useAuth } from "@tetrac/login-sdk/react";

export function EmailSignup() {
  const { registerWithEmail, loginWithEmail, status, publicKey } = useAuth();
  const [email, setEmail] = useState("");
  const [passkey, setPasskey] = useState("");

  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        try {
          await registerWithEmail({ email, passkey });
        } catch (err) {
          // 409 → account exists, log in instead
          if (String(err).includes("already exists")) {
            await loginWithEmail({ email, passkey });
          } else {
            throw err;
          }
        }
      }}
    >
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="password" value={passkey} onChange={(e) => setPasskey(e.target.value)} />
      <button type="submit">Continue</button>
      <p>status: {status} — pubKey: {publicKey ?? "—"}</p>
    </form>
  );
}
```

### Web3 wallet (Solana / Phantom)

`signMessage` must be a function returning `Uint8Array`. With
`@solana/wallet-adapter-react` it's `wallet.adapter.signMessage`.

```tsx
"use client";
import { useWallet as useSolanaWallet } from "@solana/wallet-adapter-react";
import { useAuth } from "@tetrac/login-sdk/react";

export function WalletLoginButton() {
  const solana = useSolanaWallet();
  const { connectWallet } = useAuth();

  return (
    <button
      disabled={!solana.connected || !solana.publicKey || !solana.signMessage}
      onClick={async () => {
        // connectWallet = login if known, register if new — single call.
        await connectWallet({
          publicKey: solana.publicKey!.toBase58(),
          signMessage: solana.signMessage!,
        });
      }}
    >
      Continue with wallet
    </button>
  );
}
```

The user will be prompted to sign **two** messages — one over the random
challenge (proves ownership, server-verified, replay-safe) and one over a fixed
string (`WALLET_APP_KEY_MESSAGE`, derives the encryption key locally — never
leaves the device). The second signature is what makes the wallets decryptable
on any device for that wallet.

### Biometric (Touch ID / Face ID)

```tsx
"use client";
import { useEffect, useState } from "react";
import { useAuth } from "@tetrac/login-sdk/react";
import { isBiometricAvailable, type PasskeyRegistration } from "@tetrac/login-sdk/client";

export function BiometricLogin() {
  const { registerWithBiometric, loginWithBiometric } = useAuth();
  const [available, setAvailable] = useState(false);
  // Persist the registration locally so the user can re-login on this device.
  const [reg, setReg] = useState<PasskeyRegistration | null>(() => {
    if (typeof window === "undefined") return null;
    const raw = localStorage.getItem("ttc-passkey-reg");
    return raw ? (JSON.parse(raw) as PasskeyRegistration) : null;
  });

  useEffect(() => {
    isBiometricAvailable().then(setAvailable);
  }, []);

  if (!available) return <p>Biometric not available on this device.</p>;

  return reg ? (
    <button onClick={() => loginWithBiometric({ registration: reg })}>
      Unlock with Touch ID
    </button>
  ) : (
    <button
      onClick={async () => {
        const { registration } = await registerWithBiometric({ userName: "me@example.com" });
        localStorage.setItem("ttc-passkey-reg", JSON.stringify(registration));
        setReg(registration);
      }}
    >
      Enable biometric login
    </button>
  );
}
```

> Storing the `PasskeyRegistration` in `localStorage` is just a lookup record
> (credential ID + salt + mode). It contains **no** secret — the actual key
> material stays in the platform authenticator (PRF mode) or behind a biometric
> gate in IndexedDB (gate mode).

### Reading the active session

```tsx
"use client";
import { useAuth, useSigner } from "@tetrac/login-sdk/react";

export function Session() {
  const { status, publicKey, email, isAuthenticated, logout } = useAuth();
  const { unlocked } = useSigner();
  if (!isAuthenticated) return <p>Not signed in.</p>;
  return (
    <div>
      <p>{email ?? publicKey}</p>
      <p>status: {status} · wallets: {unlocked ? "unlocked" : "locked"}</p>
      <button onClick={logout}>Sign out</button>
    </div>
  );
}
```

`status` values:
- `authenticated` — token + public key + app key all present.
- `session_expired` — token + public key present, app key missing (tab was
  reloaded after closing all tabs; wallets can't be decrypted until re-auth).
- `unauthenticated` — nothing.

### Loaded wallets (`useUser`, `useWallets`, `useActiveWallet`)

Once `<AuthProvider>` is mounted, it fetches `/api/auth/user-data` whenever the
session becomes authenticated and caches the result. Three hooks read it:

```tsx
"use client";
import { useUser, useWallets, useActiveWallet } from "@tetrac/login-sdk/react";

function WalletList() {
  const { user, loading, refetch } = useUser();
  const wallets = useWallets();        // every wallet, embedded + external
  const active = useActiveWallet();    // the one to sign/display with (Solana by default)

  if (loading) return <p>Loading wallets…</p>;
  if (!user) return null;

  return (
    <div>
      <p>Active: {active?.address} ({active?.isEmbedded ? "embedded" : "external"})</p>
      <ul>
        {wallets.map((w) => (
          <li key={`${w.chain}:${w.address}`}>{w.chain}/{w.role} — {w.address}</li>
        ))}
      </ul>
      <button onClick={refetch}>Refetch</button>
    </div>
  );
}
```

- `useUser()` → `{ user: UserData | null, loading, refetch }`. Auto-refetches on
  login/logout; call `refetch()` after a mutation (e.g. `importWallet`).
- `useWallets()` → `WalletEntry[]` — `{ chain, role, address, isEmbedded, encrypted }`.
  Embedded entries carry the `EncryptedWallet` blob; external entries set `encrypted: null`.
- `useActiveWallet({ chain? = "solana" })` → the single wallet to sign with for that chain.
  External-connected-wins rule for Solana; embedded `funds` otherwise.

**Wiring an external Solana wallet (Phantom/Backpack/etc.):** the SDK doesn't
depend on `@solana/wallet-adapter-react` — pipe the connected address in via
the `externalSolanaAddress` prop:

```tsx
"use client";
import { useWallet as useSolanaWallet } from "@solana/wallet-adapter-react";
import { AuthProvider } from "@tetrac/login-sdk/react";

function AuthBridge({ children }: { children: React.ReactNode }) {
  const external = useSolanaWallet();
  return (
    <AuthProvider
      apiBaseUrl="/api/auth"
      walletGen={{ solana: ["funds"] }}
      externalSolanaAddress={external.publicKey?.toBase58() ?? null}
    >
      {children}
    </AuthProvider>
  );
}
```

When `externalSolanaAddress` is set, `useActiveWallet()` returns that address
with `isEmbedded: false` and `encrypted: null` — sign through the external
adapter, not via `useSolanaSigner` (which only handles embedded blobs). Compose
the two:

```tsx
const active = useActiveWallet();
const embeddedSigner = useSolanaSigner(active?.encrypted ?? null);
const externalSigner = useSolanaWallet();

const signTransaction = active?.isEmbedded
  ? embeddedSigner?.signTransaction
  : externalSigner.signTransaction;
```

---

## 5. Vanilla browser client (no React)

`AuthClient` is the same engine the React hooks wrap.

```ts
import { createAuthClient } from "@tetrac/login-sdk/client";

const auth = createAuthClient({
  apiBaseUrl: "/api/auth",
  walletGen: { solana: ["funds", "signing"], evm: ["funds"] },
});

// 1) Email + passkey
await auth.registerWithEmail({ email: "a@b.com", passkey: "correct horse battery staple" });

// 2) Web3 wallet
await auth.connectWallet({
  publicKey: phantom.publicKey!.toBase58(),
  signMessage: (msg) => phantom.signMessage(msg),
});

// 3) Biometric
const { registration } = await auth.registerWithBiometric({ userName: "a@b.com" });
// Save `registration` somewhere — IndexedDB / localStorage — so the same device
// can re-login: await auth.loginWithBiometric({ registration }).

// Session inspection
import { getAuthStatus, getPublicKey, getAppKey, authHeaders } from "@tetrac/login-sdk/client";

getAuthStatus();             // "authenticated" | "session_expired" | "unauthenticated"
getPublicKey();              // string | null
getAppKey();                 // string | null  (the encryption key — DO NOT log/send)
authHeaders();               // { "ttc-auth-token", "ttc-public-key" } for fetch()

// Logout
auth.logout();
```

---

## 6. Plain Node.js backend (Express / Fastify / Hono)

The SDK route handlers are built on the standard `Request` / `Response` Web API,
so any framework that can adapt to those works.

### Hono (cleanest — same Web API)

```ts
import { Hono } from "hono";
import { createAuthHandlers } from "@tetrac/login-sdk/server";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter();
const handlers = createAuthHandlers({ storage });
const app = new Hono();

app.post("/auth/challenge",      (c) => handlers.challenge(c.req.raw));
app.post("/auth/register",       (c) => handlers.register(c.req.raw));
app.post("/auth/login",          (c) => handlers.login(c.req.raw));
app.post("/auth/login-wallet",   (c) => handlers.loginWallet(c.req.raw));
app.post("/auth/connect-wallet", (c) => handlers.connectWallet(c.req.raw));
app.post("/auth/import-wallet",  (c) => handlers.importWallet(c.req.raw));
app.get("/auth/user-data",       (c) => handlers.userData(c.req.raw));
app.get("/auth/search-wallet",   (c) => handlers.searchWallet(c.req.raw));

export default app;
```

### Express (needs a Web-Request shim)

Express uses Node's `IncomingMessage`, not the Fetch `Request`. Convert at the
edge:

```ts
import express from "express";
import { createAuthHandlers } from "@tetrac/login-sdk/server";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter();
const handlers = createAuthHandlers({ storage });
const app = express();

// Body parsing happens inside the SDK (req.json()), so DON'T add express.json()
// for the SDK paths — keep the body unread.

async function toWebRequest(req: express.Request): Promise<Request> {
  const proto = (req.headers["x-forwarded-proto"] as string) ?? "http";
  const url = `${proto}://${req.headers.host}${req.originalUrl}`;
  const method = req.method;
  // Drain the raw body once.
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  return new Request(url, {
    method,
    headers: req.headers as Record<string, string>,
    body: method === "GET" || method === "HEAD" ? undefined : body,
  });
}

async function send(res: express.Response, webRes: Response) {
  res.status(webRes.status);
  webRes.headers.forEach((v, k) => res.setHeader(k, v));
  const text = await webRes.text();
  res.send(text);
}

const route =
  (h: (r: Request) => Promise<Response>) =>
  async (req: express.Request, res: express.Response) => {
    send(res, await h(await toWebRequest(req)));
  };

app.post("/auth/challenge",      route(handlers.challenge));
app.post("/auth/register",       route(handlers.register));
app.post("/auth/login",          route(handlers.login));
app.post("/auth/login-wallet",   route(handlers.loginWallet));
app.post("/auth/connect-wallet", route(handlers.connectWallet));
app.post("/auth/import-wallet",  route(handlers.importWallet));
app.get("/auth/user-data",       route(handlers.userData));
app.get("/auth/search-wallet",   route(handlers.searchWallet));

app.listen(3000);
```

> The Hono path is preferred for new services — it's what the Next.js binding
> uses under the hood and there's no impedance mismatch.

### Wiring storage explicitly (no auto-resolve)

`resolveStorageAdapter()` is a convenience. To pick the adapter yourself:

```ts
import { Redis } from "@upstash/redis";
import { UpstashAdapter } from "@tetrac/login-sdk/storage";

const storage = new UpstashAdapter(
  new Redis({ url: process.env.UPSTASH_REDIS_REST_URL!, token: process.env.UPSTASH_REDIS_REST_TOKEN! })
);
```

```ts
import IORedis from "ioredis";
import { RedisAdapter } from "@tetrac/login-sdk/storage";

const storage = new RedisAdapter(new IORedis(process.env.REDIS_URL!));
```

```ts
import { kv } from "@vercel/kv";
import { VercelKVAdapter } from "@tetrac/login-sdk/storage";

const storage = new VercelKVAdapter(kv);
```

For tests:

```ts
import { MemoryAdapter } from "@tetrac/login-sdk/storage";
const storage = new MemoryAdapter();
```

---

## 7. Verifying sessions in your own routes

`verifySession` looks up the opaque session token in storage and returns the
`UserData` row (or `null`).

```ts
// app/api/portfolio/route.ts  (Next.js App Router)
import { verifySession } from "@tetrac/login-sdk/server";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";
import { resolveConfig } from "@tetrac/login-sdk/core";

const storage = await resolveStorageAdapter();
const config = resolveConfig();

export async function GET(req: Request) {
  const user = await verifySession(
    storage,
    req.headers.get(config.sessionHeader),       // "ttc-auth-token"
    req.headers.get(config.publicKeyHeader),     // "ttc-public-key"
    config,
  );
  if (!user) return new Response("Unauthorized", { status: 401 });

  // user.publicKey, user.email, user.wallets (ciphertext blobs only)
  return Response.json({ wallets: user.wallets.map((w) => ({ chain: w.chain, role: w.role, publicKey: w.publicKey })) });
}
```

The client attaches the headers automatically when you call any helper that
goes through `AuthClient`. For your own `fetch` calls:

```ts
import { authHeaders } from "@tetrac/login-sdk/client";

const res = await fetch("/api/portfolio", { headers: authHeaders() });
```

> The server never sees `appKey` and can never decrypt user wallets. Anything
> that needs to spend funds must happen client-side using `useSigner` (or the
> `withDecryptedKey` helper).

---

## 8. Wallet generation & decrypt-to-sign

### Generate a bundle directly (e.g. when bringing your own auth UI)

```ts
import {
  generateWalletBundle,
  flattenBundle,
  toSolanaKeypair,
  withDecryptedKey,
} from "@tetrac/login-sdk/client";
import {
  deriveAppKeyFromPasskey,
  deriveAppKeyFromSignature,
} from "@tetrac/login-sdk/core";

// From passkey + email (email/biometric flows)
const appKey = deriveAppKeyFromPasskey("correct horse battery staple", "a@b.com", 100_000);

// OR from a wallet signature (Web3 flow)
// const appKey = deriveAppKeyFromSignature(signatureHex);

const bundle = generateWalletBundle({
  appKey,
  solana: ["funds", "signing"],
  evm:    ["funds", "signing"],
});

bundle.solana!.funds.publicKey;     // base58 string
bundle.evm!.signing.publicKey;      // 0x address
flattenBundle(bundle);              // EncryptedWallet[] — safe to POST
```

### Decrypt to sign (Solana)

```ts
import { Transaction } from "@solana/web3.js";
import { useSigner } from "@tetrac/login-sdk/react";

const { solanaKeypair, sign } = useSigner();

// Cheap: reconstruct a Keypair for a quick signature.
const kp = solanaKeypair(user.wallets.find((w) => w.chain === "solana" && w.role === "signing")!);
tx.partialSign(kp);

// Lifetime-bounded version — clears the secret reference after the callback.
await sign(signingWallet, async (secretHex) => {
  const kp = /* rebuild Keypair from secretHex */;
  tx.partialSign(kp);
  return tx.serialize();
});
```

### Decrypt to sign (EVM via viem)

```ts
import { privateKeyToAccount } from "viem/accounts";
import { useSigner } from "@tetrac/login-sdk/react";

const { sign } = useSigner();
const evmSigning = user.wallets.find((w) => w.chain === "evm" && w.role === "signing")!;

const signature = await sign(evmSigning, async (pkHex) => {
  const account = privateKeyToAccount(pkHex as `0x${string}`);
  return account.signMessage({ message: "Authorize TTC trade #42" });
});
```

`withDecryptedKey` / `sign` drop the in-memory secret string as soon as the
callback returns. Keep the callback tight — don't `await` long-running
network calls while holding the decrypted key.

### High-level signers (`useSolanaSigner`, `useEvmSigner`)

The hooks above are the security-critical core. For most app code you want
ready-made signer objects that match the conventions of the rest of the
ecosystem — drop them into Anchor, viem, wagmi, etc., and forget about the
decrypt envelope.

**Solana — `@solana/wallet-adapter-react` shape:**

```tsx
"use client";
import { useSolanaSigner } from "@tetrac/login-sdk/react";
import { AnchorProvider, Program } from "@coral-xyz/anchor";
import { Connection } from "@solana/web3.js";

function useMyProgram(walletBlob, connection: Connection) {
  const signer = useSolanaSigner(walletBlob);   // null until session unlocks
  if (!signer) return null;
  const provider = new AnchorProvider(connection, signer, { commitment: "confirmed" });
  return new Program(IDL, provider);
}
```

Returns `{ publicKey, signTransaction, signAllTransactions, signMessage }` —
the same shape Anchor's `Wallet` interface and the Solana wallet adapter
expect. Each signing call decrypts the secret, signs, and zeroes the secret
bytes before returning.

**EVM — viem `LocalAccount`:**

```tsx
"use client";
import { useEvmSigner } from "@tetrac/login-sdk/react";
import { createWalletClient, http } from "viem";
import { base } from "viem/chains";

function useViemClient(walletBlob) {
  const account = useEvmSigner(walletBlob);   // null until session unlocks
  if (!account) return null;
  return createWalletClient({ account, chain: base, transport: http() });
}
```

The returned `LocalAccount` plugs straight into `createWalletClient`, wagmi's
custom-connector pattern, or anywhere a viem account is accepted. RPC/chain
config stays in your app — the SDK only owns the signer.

Both hooks return `null` when no wallet is passed in or the session is locked,
so you can render conditionally without extra guards.

---

## 9. Custom storage adapter

Implement the `StorageAdapter` interface to plug in anything (DynamoDB, SQLite,
in-process map for tests):

```ts
import type { StorageAdapter } from "@tetrac/login-sdk/storage";

class MyAdapter implements StorageAdapter {
  async get(key: string): Promise<string | null> { /* ... */ }
  async set(key: string, value: string, opts?: { exSeconds?: number }): Promise<void> { /* ... */ }
  async del(key: string): Promise<void> { /* ... */ }
  async incr(key: string): Promise<number> { /* ... */ }   // rate-limit counters
  async expire(key: string, seconds: number): Promise<void> { /* ... */ }
}

export const { GET, POST } = createNextAuthRoutes({ storage: new MyAdapter() });
```

Required semantics:
- `set` with `exSeconds` sets a TTL.
- `incr` must be atomic — it backs rate limiting.
- `expire` is called immediately after the first `incr` of a window, so an
  implementation that supports `set` + `incr` only needs to honor TTL on
  subsequent reads.

---

## 10. Configuration overrides

```ts
import type { AuthConfig } from "@tetrac/login-sdk/core";

const config: Partial<AuthConfig> = {
  pbkdf2Iterations: 250_000,
  challengeTtlSeconds: 60,
  sessionHeader: "x-app-token",            // must match on client and server
  publicKeyHeader: "x-app-pubkey",
  keyPrefixes: {
    challenge: "myapp:chal:",
    pubKey:    "myapp:user:",
    email:     "myapp:email:",
    rateLimit: "myapp:rl:",
  },
  rateLimit: { windowSeconds: 60, maxAttempts: 5 },
  webauthn: { rpId: "auth.example.com", rpName: "Example", preferPrf: true },
};
```

Apply on server **and** client:

```ts
// server
createNextAuthRoutes({ storage, config });

// client
new AuthClient({ apiBaseUrl: "/api/auth", config });
// or
<AuthProvider apiBaseUrl="/api/auth" config={config}>...</AuthProvider>
```

---

## 11. Common patterns & gotchas

**Two-signature wallet flow.** `loginWithWallet` / `connectWallet` prompt the
user to sign twice: once over the random challenge (auth), once over the fixed
`WALLET_APP_KEY_MESSAGE` (derives the encryption key locally). Surface this in
your UI so users aren't surprised by the second prompt.

**App key is sessionStorage, not localStorage.** Closing every tab clears the
encryption key. On the next visit the user appears `session_expired` and must
re-auth (re-enter passkey / re-sign with wallet / re-biometric) so the key can
be re-derived. The auth token alone is not enough to read wallets.

**Storage adapter is server-only.** Never import `@tetrac/login-sdk/storage` from a
client component — it pulls Redis/KV drivers. If you accidentally do, Next will
warn about Node built-ins in the browser bundle.

**Runtime.** `ioredis` requires the Node runtime. If you deploy to the edge,
use `UpstashAdapter` and set `export const runtime = "edge"`. The Vercel KV
adapter works on both.

**Rate limiting is dual-key.** Each route is limited per-IP **and**
per-identifier (email or pubKey). Defaults: 10 attempts / 60s. Override per
deployment via `config.rateLimit`.

**Account collisions.** `register` returns `409 Account already exists` when
the `publicKey` is taken. Catch and fall back to `login` (see the email signup
example).

**`connectWallet` is the easy button.** Prefer it for Web3 flows — one round
trip, registers if new, logs in if known. Use `registerWithWallet` /
`loginWithWallet` only when you need them distinct (e.g. an explicit "sign up"
vs "sign in" UI).

**Custom wallet roles.** `WalletRole` is `"funds" | "signing" | (string & {})`
— you can ask for arbitrary roles (`["funds", "signing", "savings"]`) and
they'll round-trip through the bundle and storage.

**Empty wallet self-heal.** `connectWallet` will backfill an existing wallet
record if it has zero wallets stored (e.g. a legacy account that was created
before client-side generation existed). Existing wallets with any keys are
never overwritten — the deterministic encryption key guarantees the ciphertext
already on file is valid.

**Testing.** Use `MemoryAdapter` for unit tests; it's API-complete (TTL, incr,
expire) and stateless across instances.

---

For deeper background (security model, key derivation, threat model) see
[`PRD.md`](./PRD.md) §5 and §10.
