# @tetrac/login-sdk

Reusable, **non-custodial** authentication SDK: **email/passkey**, **Web3 wallet**, and
**biometric (WebAuthn PRF)** login, with **client-side wallet generation** built in.
Storage runs on local **Redis** in dev and **Upstash / Vercel KV** in production.

Extracted from the `next-ttc` trading platform so any project can drop in the same auth.

> Status: `v0.1.0` — see [`docs/PRD.md`](./docs/PRD.md) for the full product spec.

## Why

- **Three login methods** behind one client.
- **Wallets are generated in the browser** and AES-encrypted under a key derived from your
  passkey/signature **before** anything reaches the server. The server only ever stores
  public keys, ciphertext, and a passkey hash — never a private key, never the encryption key.
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

Endpoints served: `POST challenge | register | login | login-wallet | import-wallet`,
`GET user-data | search-wallet`.

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
bundle.evm.signing.address;          // 0x…
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

## Configuration

Defaults match `next-ttc`. Override via the `config` option on the route factory / `AuthClient`:

```ts
{
  pbkdf2Iterations: 100_000,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  sessionTtlSeconds: 86_400,        // session tokens expire server-side after 24h
  trustProxyHeaders: false,         // see "Production deployment notes" below
  keyPrefixes: { challenge: "challenge:", pubKey: "pubKey:", email: "email:", rateLimit: "ratelimit:" },
  rateLimit: { windowSeconds: 60, maxAttempts: 10 },
  webauthn: { rpName: "TTC", preferPrf: true },
  autoLockMs: 15_000,               // in-browser app key auto-locks after 15s idle
  appKeyStorage: "session",         // "memory" = stricter: reload forces re-auth
  lockOnHide: true,                 // lock the vault when the tab is hidden
  revealRequiresReauth: true,       // plaintext reveal always re-runs the ceremony
}
```

### Production deployment notes

- **Behind a trusted proxy (Vercel, Cloudflare, nginx)?** Set
  `trustProxyHeaders: true` so per-IP rate limiting uses `x-forwarded-for`.
  With the default `false`, proxy headers are ignored (they're client-spoofable
  when there's no proxy) and all traffic shares one IP bucket — safe, but it
  effectively turns the per-IP limit into a global one.
- **Sessions expire.** Tokens die server-side after `sessionTtlSeconds` (24h
  default) and each new login revokes the previous token. `logout()` revokes
  the current token best-effort via `POST /logout` before clearing local state.

### Environment

```
REDIS_URL=redis://localhost:6379        # dev
# prod (pick one):
VERCEL=1                                 # @vercel/kv
KV_REST_API_URL= / KV_REST_API_TOKEN=    # Vercel KV REST
UPSTASH_REDIS_REST_URL= / UPSTASH_REDIS_REST_TOKEN=
```

## Security model

- Private keys: encrypted at rest (AES via `crypto-es`), never stored or transmitted in plaintext.
- App/encryption key: memory + `sessionStorage` only — never `localStorage`, never sent to the server.
  Auto-locks after `autoLockMs` idle; locked signers throw `VaultLockedError` until re-auth.
- Revealing a plaintext key always re-runs the auth ceremony (passkey / wallet signature /
  Face ID) — never the ambient session key.
- Web3 login: 32-byte challenge, 5-min TTL, **single-use** (atomic consume); signature verified with `tweetnacl`.
- Biometric: WebAuthn `userVerification: required`; PRF preferred; gate fallback wraps its secret
  under a non-extractable AES-GCM key in IndexedDB.
- Optional biometric unlock (any account): the current app key is wrapped with HKDF-SHA-256 +
  authenticated AES-256-GCM under a passkey secret and stored per-device; unwrapping always needs a
  fresh biometric assertion. Purged on `disableBiometricUnlock` and on logout (`clearSession`).
  See [`features/unlockViaBiometric.md`](./features/unlockViaBiometric.md).
- Sessions: opaque 256-bit tokens, server-side TTL, revoked on re-login and logout.
- Dual-key (IP + identifier) rate limiting on all auth routes; responses never echo credential hashes.

## Develop

```bash
npm run build      # tsup -> ESM + CJS + d.ts
npm test           # jest
npm run typecheck
```

## License

MIT
