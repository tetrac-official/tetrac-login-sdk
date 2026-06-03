# @ttc/login-sdk

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
npm i @ttc/login-sdk
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
| `@ttc/login-sdk/core` | anywhere | types, config, key derivation, AES, CSPRNG |
| `@ttc/login-sdk/client` | browser | wallet generation, sessions, WebAuthn, `AuthClient` |
| `@ttc/login-sdk/server` | backend | challenge/signature/session verify, route factory |
| `@ttc/login-sdk/storage` | backend | `StorageAdapter` + Redis/Vercel KV/Upstash/Memory |
| `@ttc/login-sdk/react` | browser | `AuthProvider`, `useAuth`, `useWallet` |
| `@ttc/login-sdk/next` | Next App Router | `createNextAuthRoutes` |

## Server (Next.js App Router)

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@ttc/login-sdk/next";
import { resolveStorageAdapter } from "@ttc/login-sdk/storage";

const storage = await resolveStorageAdapter(); // Redis dev / KV / Upstash by env
export const { GET, POST } = createNextAuthRoutes({ storage });
```

Endpoints served: `POST challenge | register | login | login-wallet | import-wallet`,
`GET user-data | search-wallet`.

## Client (React)

```tsx
import { AuthProvider, useAuth } from "@ttc/login-sdk/react";

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
import { generateWalletBundle, flattenBundle, toSolanaKeypair } from "@ttc/login-sdk/client";

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

## Configuration

Defaults match `next-ttc`. Override via the `config` option on the route factory / `AuthClient`:

```ts
{
  pbkdf2Iterations: 100_000,
  challengeTtlSeconds: 300,
  sessionHeader: "ttc-auth-token",
  publicKeyHeader: "ttc-public-key",
  keyPrefixes: { challenge: "challenge:", pubKey: "pubKey:", email: "email:", rateLimit: "ratelimit:" },
  rateLimit: { windowSeconds: 60, maxAttempts: 10 },
  webauthn: { rpName: "TTC", preferPrf: true },
}
```

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
- Web3 login: 32-byte challenge, 5-min TTL, **single-use**; signature verified with `tweetnacl`.
- Biometric: WebAuthn `userVerification: required`; PRF preferred, IndexedDB gate fallback.
- Dual-key (IP + identifier) rate limiting on all auth routes.

## Develop

```bash
npm run build      # tsup -> ESM + CJS + d.ts
npm test           # jest
npm run typecheck
```

## License

MIT
