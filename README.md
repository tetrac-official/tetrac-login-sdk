# @tetrac/login-sdk

Reusable, **non-custodial** authentication SDK: **email/passkey**, **Web3 wallet**, and
**biometric (WebAuthn PRF)** login, with **client-side wallet generation** built in.
Storage runs on local **Redis** in dev and **Upstash / Vercel KV** in production.

Extracted from the `next-ttc` trading platform so any project can drop in the same auth.

> Status: `v0.3.0` — see [`docs/PRD.md`](./docs/PRD.md) for the full product spec.

## Why

- **Three login methods** behind one client.
- **Wallets are generated in the browser** and encrypted (authenticated AES-256-GCM) under a key
  derived from your passkey/signature **before** anything reaches the server. The server only ever
  stores public keys, ciphertext, and an ed25519 **auth public key** — never a private key, never the
  encryption key, and never a passkey-derived secret.
- **Deterministic recovery:** the same passkey+email (or the same wallet signature) re-derives
  the encryption key on any device, so wallets decrypt anywhere with zero server-side key storage.

## Install

```bash
npm i @tetrac/login-sdk
# peers (supply what you use):
npm i @solana/web3.js viem tweetnacl
# storage backend (pick one):
npm i ioredis            # dev (localhost)
npm i @vercel/kv         # Vercel
npm i @upstash/redis     # Upstash (edge-friendly)
# react/next bindings:
npm i react next
```

## Subpath exports

| Import | Use in | Contents |
|---|---|---|
| `@tetrac/login-sdk/core` | anywhere | types, config, key derivation, AES, CSPRNG |
| `@tetrac/login-sdk/client` | browser | wallet generation, sessions, WebAuthn, `AuthClient` |
| `@tetrac/login-sdk/server` | backend | challenge/signature/session verify, route factory |
| `@tetrac/login-sdk/storage` | backend | `StorageAdapter` + Redis/Vercel KV/Upstash/Memory |
| `@tetrac/login-sdk/react` | browser | `AuthProvider`, `useAuth`, `useUser`, `useWallets`, `useActiveWallet`, `useSigner`, `useSolanaSigner`, `useEvmSigner`, `useExportKey` |
| `@tetrac/login-sdk/ui` | browser (optional) | `LoginPanel`, `ExportKeyPanel` |
| `@tetrac/login-sdk/next` | Next App Router | `createNextAuthRoutes` |

## Server (Next.js App Router)

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";

const storage = await resolveStorageAdapter(); // Redis dev / KV / Upstash by env
export const { GET, POST } = createNextAuthRoutes({ storage });
```

Endpoints served (all under the mount point, e.g. `/api/auth/challenge`):
`POST challenge | register | login | login-wallet | connect-wallet | import-wallet | logout`,
`GET user-data | search-wallet`. `import-wallet`, `logout`, and `user-data` require the session
headers (`ttc-auth-token` + `ttc-public-key`); the rest are public, though several still require a
single-use challenge + signature **in the request body**. Unknown actions return `404`; only `GET`/`POST`
are served.

## Client (React)

```tsx
import { AuthProvider, useAuth } from "@tetrac/login-sdk/react";

function Root() {
  return (
    <AuthProvider apiBaseUrl="/api/auth">
      <LoginButtons />
    </AuthProvider>
  );
}

function LoginButtons() {
  const { status, registerWithEmail, loginWithWallet, registerWithBiometric } = useAuth();

  // 1) Email + passkey — generates & encrypts wallets client-side
  const email = () => registerWithEmail({ email: "a@b.com", passkey: "••••••" });

  // 2) Web3 wallet (e.g. Phantom via wallet-adapter)
  const wallet = (adapter) =>
    loginWithWallet({ publicKey: adapter.publicKey.toBase58(), signMessage: adapter.signMessage });

  // 3) Biometric (Touch ID / Face ID, WebAuthn PRF)
  const bio = () => registerWithBiometric({ userName: "a@b.com" });

  return <>status: {status}</>;
}
```

### Generating wallets directly

```ts
import { generateWalletBundle, flattenBundle, toSolanaKeypair } from "@tetrac/login-sdk/client";

const bundle = generateWalletBundle({
  appKey,                       // derived from passkey+email or wallet signature
  solana: ["funds", "signing"], // funds = holds assets; signing = agent wallet
  evm:    ["funds", "signing"],
});

bundle.solana.funds.publicKey;       // base58
bundle.evm.signing.publicKey;        // 0x… (EVM address)
flattenBundle(bundle);               // public keys + ciphertext only -> safe to send

// decrypt-to-sign (key released right after the callback)
const kp = toSolanaKeypair(bundle.solana.funds, appKey);
```

### Optional biometric unlock (any account)

Any account — **email, Web3, or biometric-primary** — can opt into unlocking the vault (and
revealing/​signing) with a device biometric (Touch ID / Face ID) instead of re-entering a passkey
or re-signing a wallet message. The biometric secret does **not** replace the app key (that only
works for biometric-primary accounts); it **wraps** the account's existing app key with
HKDF-SHA-256 + AES-256-GCM. Enable requires an unlocked vault; unlock always needs a fresh
assertion, so a storage-scraping XSS reads ciphertext it can never open. It is per-device and
**never** the recovery path — the account's primary credential stays the cross-device fallback.

```tsx
import { useBiometricUnlock } from "@tetrac/login-sdk/react";

function BiometricToggle() {
  const { available, isEnabled, enable, disable, unlock, loading } = useBiometricUnlock();
  if (!available) return null;
  return isEnabled
    ? <button disabled={loading} onClick={() => disable()}>Disable biometric unlock</button>
    : <button disabled={loading} onClick={() => enable("a@b.com")}>Enable biometric unlock</button>;
  // After an auto-lock, call unlock() to re-arm the vault via Touch ID.
}
```

Once enabled, reveal/​unlock anywhere `ReauthCredentials` is accepted via the new
`{ biometricUnlock: registration }` variant (e.g. `reveal({ biometricUnlock: reg })`). Do **not**
confuse it with `{ registration }`, which is the biometric-**primary** flow where the secret *is*
the app key — the two resolve to different keys and are not interchangeable. The same functions are
available standalone from `@tetrac/login-sdk/client`
(`enableBiometricUnlock` / `unlockViaBiometric` / `disableBiometricUnlock` / `hasBiometricUnlock`)
and as `AuthClient` methods. Full design: [`features/unlockViaBiometric.md`](./features/unlockViaBiometric.md).

## Chain scope: Solana vs EVM

Both chains can have wallets generated and stored, but only one is an **authentication identity** — by design:

| Capability | Solana | EVM |
|---|---|---|
| External-wallet **login / registration** (prove ownership of a connected wallet) | ✅ ed25519 signature over the challenge | ❌ by design |
| Wallet **generated client-side & encrypted** under the app key | ✅ | ✅ |
| Stored server-side as **public key + ciphertext** | ✅ | ✅ |
| Used for **internal signing** | ✅ `useSolanaSigner` | ✅ `useEvmSigner` (viem `LocalAccount`) |
| Server **signature verification** | ✅ `verifySolanaSignature` | ❌ none (intentional) |

External-wallet auth (`authMethod: "wallet"`) is gated **solely** on `verifySolanaSignature`; submitting an
EVM address as a wallet identity returns `401`. There is intentionally **no `verifyEvmSignature`** — EVM
keypairs are *internally* generated (viem) and encrypted exactly like Solana wallets, used for **signing
only**, never as a login credential. The security boundary: **Solana = Web3 login identity; EVM (and any
other generated keypair) = internal signing wallet only.**

## Configuration

Override any subset via the `config` option on the route factory / `AuthClient`; unspecified fields
fall back to `DEFAULT_CONFIG` (nested groups merge shallowly). Defaults shown:

```ts
{
  appId: "ttc",                     // OVERRIDE IN PROD: unique + stable per deployment; domain-separates
                                    // every app key (PBKDF2 salt + wallet sign-message). Default = no
                                    // cross-app isolation (warns); changing it later re-derives all keys.
  securityLevel: 2,                 // PBKDF2 iters for email/passkey: 1=100k, 2=600k (default), 3=1M;
                                    // the resolved count is pinned per-user at registration.
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  sessionTtlSeconds: 14_400,        // session tokens expire server-side after 4h
  trustProxyHeaders: false,         // see "Production deployment notes" below
  trustedProxyHops: 0,              // when trustProxyHeaders: take the rightmost XFF entry after N trusted hops
  keyPrefixes: { challenge: "challenge:", pubKey: "pubKey:", session: "session:", email: "email:", rateLimit: "ratelimit:" },
  rateLimit: { windowSeconds: 60, maxAttempts: 10 },
  webauthn: { rpName: "TTC", preferPrf: true },
  autoLockMs: 15_000,               // in-browser app key auto-locks after 15s idle
  lockOnHide: true,                 // lock the vault when the tab is hidden / frozen
  revealRequiresReauth: true,       // plaintext reveal always re-runs the ceremony
  maxWalletsPerUser: 64,            // import-wallet total cap (record-bloat guard)
}
```

> The in-browser app/encryption key is **memory-only** — there is no `sessionStorage`/`localStorage`
> option to configure. `appId` **must** be set to a unique, stable value per deployment in production;
> the default `"ttc"` gives no cross-app key isolation.

### Production deployment notes

- **Behind a trusted proxy (Vercel, Cloudflare, nginx)?** Set
  `trustProxyHeaders: true` so per-IP rate limiting uses `x-forwarded-for`.
  With the default `false`, proxy headers are ignored (they're client-spoofable
  when there's no proxy) and all traffic shares one IP bucket — safe, but it
  effectively turns the per-IP limit into a global one.
- **Sessions expire.** Tokens die server-side after `sessionTtlSeconds` (4h
  default) and each new login revokes the previous token. `logout()` revokes
  the current token best-effort via `POST /logout` (with `keepalive` so it lands
  during unload) before clearing local state; clearing the shared token also locks
  sibling tabs of the same origin.

### Environment

```
REDIS_URL=redis://localhost:6379        # dev
# prod (pick one):
VERCEL=1                                 # @vercel/kv
KV_REST_API_URL= / KV_REST_API_TOKEN=    # Vercel KV REST
UPSTASH_REDIS_REST_URL= / UPSTASH_REDIS_REST_TOKEN=
```

## Security model

- Private keys: encrypted at rest with **authenticated AES-256-GCM** (Web Crypto) — a wrong key or any
  tampering throws on decrypt; never stored or transmitted in plaintext.
- Key derivation + hashing use **`@noble/hashes`** (no `crypto-es`): email/passkey app keys are
  **PBKDF2-HMAC-SHA256** with iterations from `securityLevel` (1=100k, 2=600k default, 3=1M), pinned
  per-user; Web3 app keys are `SHA-256` over a fixed wallet message.
- **`appId` domain separation:** `appId` is mixed into both derivations (the PBKDF2 salt
  `SHA-256(appId:email)` and the wallet sign-message), so the same user/wallet derives a *different*
  app key per deployment — a key cracked or coerced on one app can't unlock the same user on another.
- App/encryption key: **memory-only** — never `sessionStorage`, never `localStorage`, never sent to the
  server. A tab reload (or crash) drops it, so the user must re-authenticate to decrypt wallets and
  storage-scraping XSS finds no key at rest. Auto-locks after `autoLockMs` idle and on tab hide / page
  freeze / bfcache restore; locked signers throw `VaultLockedError` until re-auth. To survive a reload
  without re-running a passkey ceremony, use **biometric unlock** (a Touch/Face-ID-gated wrapped blob).
- Revealing a plaintext key always re-runs the auth ceremony (passkey / wallet signature /
  Face ID) — never the ambient session key.
- **Authentication is by signature — no server-stored passkey hash.** Every account signs a single-use
  32-byte challenge (5-min TTL, atomic consume). Email/biometric accounts sign with an ed25519 keypair
  derived from the app key; the server stores **only** the public key (`authPublicKey`) and verifies the
  signature. Web3 logins verify a Solana signature with `tweetnacl`.
- Biometric: WebAuthn `userVerification: required`; PRF preferred; gate fallback wraps its secret
  under a non-extractable AES-GCM key in IndexedDB.
- Optional biometric unlock (any account): the current app key is wrapped with HKDF-SHA-256 +
  authenticated AES-256-GCM under a passkey secret and stored per-device; unwrapping always needs a
  fresh biometric assertion. Purged on `disableBiometricUnlock` and on logout (`clearSession`).
  See [`features/unlockViaBiometric.md`](./features/unlockViaBiometric.md).
- Sessions: opaque 256-bit bearer tokens, **single active session** (each login revokes the prior token),
  server-side TTL (**4h default**). `logout()` revokes via `POST /logout` with `keepalive` so it lands
  during page unload.
- Rate limiting is **per-target** (e.g. `login:<email>`, `challenge:<id>`) plus a per-IP bucket when
  behind a trusted proxy (`trustProxyHeaders` / `trustedProxyHops`), so a flood on one target can't lock
  out everyone. Responses never echo credential secrets.

## Develop

```bash
npm run build      # tsup -> ESM + CJS + d.ts
npm test           # jest
npm run typecheck
```

## License

MIT
