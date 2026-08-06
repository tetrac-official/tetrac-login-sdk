# @tetrac/login-sdk

Non-custodial authentication for Next.js and React — email/passkey, Web3 wallet, and biometric
(WebAuthn PRF) login with client-side wallet generation. Bring your own database.

Private keys are generated and encrypted in the browser. The server stores ciphertext and a public
key, never a key it can decrypt and never a replayable session credential.

[![npm](https://img.shields.io/npm/v/@tetrac/login-sdk.svg)](https://www.npmjs.com/package/@tetrac/login-sdk)
[![license](https://img.shields.io/npm/l/@tetrac/login-sdk.svg)](./LICENSE)

## Install

```bash
npm i @tetrac/login-sdk @solana/web3.js tweetnacl
```

Node ≥ 18. React and Next are optional peers — add them only if you use the React or Next entry
points. Then install **one** storage driver:

```bash
npm i pg                # Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly, CockroachDB
npm i mysql2            # MySQL, MariaDB
npm i better-sqlite3    # SQLite, libSQL, Turso
npm i @upstash/redis    # Upstash (edge-compatible)
npm i ioredis           # self-hosted or managed Redis (Node runtime only)
```

Optional extras: `viem` for EVM wallets, `@ledgerhq/hw-app-solana` + a transport for Ledger.

## Server

One catch-all route serves every endpoint.

```ts
// app/api/auth/[...action]/route.ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
import { createPostgresAuthStore } from "@tetrac/login-sdk/storage/sql";
import { Pool } from "pg";

const store = await createPostgresAuthStore({ client: new Pool() });

export const { GET, POST } = createNextAuthRoutes({
  store,
  config: {
    appId: "myapp.example",
    origin: "https://myapp.example",
    allowedAppIds: ["myapp.example"],
  },
});
```

Generate the schema once with `schemaFor("postgres" | "mysql" | "sqlite")` and run it against your
database. Redis-family backends use `{ storage }` instead of `{ store }`:

```ts
import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";
const storage = await resolveStorageAdapter();   // reads Upstash / Vercel KV / REDIS_URL from env
```

## Client

```tsx
// app/providers.tsx
"use client";
import { AuthProvider } from "@tetrac/login-sdk/react";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider apiBaseUrl="/api/auth" config={{ appId: "myapp.example" }}>
      {children}
    </AuthProvider>
  );
}
```

## Configuration

`config` is a deep-partial of `AuthConfig`, accepted by both `createNextAuthRoutes` and
`AuthProvider`. Set `appId` and `origin` identically on both.

### Identity — permanent, set once

Both are app-key derivation input. **Changing either re-derives every app key and existing encrypted
wallets stop decrypting.**

| Option | Default | |
|---|---|---|
| `appId` | `"ttc"` | Per-deployment identifier. Domain-separates key derivation and namespaces every storage key, so several apps can share one database. The default provides no isolation — override it. |
| `origin` | *(required on the server)* | Canonical origin, e.g. `"https://myapp.example"` — scheme + host (+ port), no path or trailing slash. Binds wallet signatures to your site so they cannot be relayed from another. Defaults to `window.location.origin` in the browser. |
| `allowedAppIds` | *(unset)* | Accepted `appId` values. Unset, any well-formed `appId` mints a namespace — a client sending the wrong one registers into a separate tenant under a different key. Warns at boot. |

### Key derivation

| Option | Default | |
|---|---|---|
| `securityLevel` | `2` | PBKDF2-HMAC-SHA256 iterations for email accounts: `1` = 100k, `2` = 600k (OWASP 2023 minimum), `3` = 1M. The resolved count is pinned per user at registration, so changing this never orphans an existing account. |

### Sessions and challenges

| Option | Default | |
|---|---|---|
| `sessionTtlSeconds` | `86400` | Session lifetime. A backstop only — each login revokes the previous token immediately. |
| `challengeTtlSeconds` | `300` | Login-challenge lifetime. |
| `bindSessionToUserAgent` | `false` | Bind each session to `SHA-256(user-agent)`. Coarse; a browser update logs the user out. |

### Rate limiting

| Option | Default | |
|---|---|---|
| `rateLimit` | `{ windowSeconds: 60, maxAttempts: 10 }` | General per-endpoint limit. |
| `accountCreationRateLimit` | `{ windowSeconds: 60, maxAttempts: 2 }` | Deployment-wide ceiling on **new accounts**, charged only when a record is created. Not app-scoped and not keyed on anything the caller supplies, so there is nothing to rotate. |
| `trustProxyHeaders` | `false` | Honor `x-forwarded-for`. Enable **only** behind a proxy you operate — on a directly reachable app the header is caller-supplied and trusting it is worse than leaving the per-IP limit off. Warns at boot while unset. |
| `trustedProxyHops` | `0` | Proxies to skip from the right of `x-forwarded-for`. `0` = a single trusted edge (e.g. Vercel). |

### Browser vault

The app key is held in memory only — never in `localStorage` or `sessionStorage`.

| Option | Default | |
|---|---|---|
| `autoLockMs` | `15000` | Idle timeout before the vault locks. Signing then throws `VaultLockedError` until re-auth. |
| `lockOnHide` | `true` | Also lock on tab hide, page freeze, and bfcache restore. |
| `revealRequiresReauth` | `true` | Revealing a plaintext key always runs a fresh re-auth ceremony rather than using the ambient session key. |

### WebAuthn

| Option | Default | |
|---|---|---|
| `webauthn.rpName` | `"TTC"` | Relying-party name shown in the biometric prompt. |
| `webauthn.rpId` | *(unset)* | Relying-party ID; must match the site's registrable domain. |

The WebAuthn PRF extension is **required** for every biometric flow. An authenticator without it
throws `PrfUnavailableError` — there is no opt-out and no fallback mode. Catch it and offer
email + passkey instead.

### Storage keys

| Option | Default | |
|---|---|---|
| `keyPrefixes` | `challenge:` `pubKey:` `session:` `email:` `ratelimit:` | Key namespaces. Override only to share a database with unrelated keys; prefixes must stay mutually disjoint. |

### Client-only options

Passed to `AuthProvider` / `createAuthClient` alongside `config`.

| Option | Default | |
|---|---|---|
| `apiBaseUrl` | *(required)* | Base URL of the auth API, e.g. `"/api/auth"`. |
| `walletGen` | `{ solana: ["funds","signing"], evm: ["funds","signing"] }` | Which wallets to generate at sign-up. A record holds at most one wallet per `(chain, role)`. |
| `externalSolanaAddress` | `null` | Address of a connected external wallet; `useActiveWallet()` returns it in place of the embedded funds wallet. |

### Boot warnings

`createAuthHandlers` reports configuration hazards at startup. Route them into your logger with
`onWarning`; each names the consequence, not just the setting.

```ts
createNextAuthRoutes({ store, config, onWarning: (w) => logger.warn(w.code, w.message) });
```

| Code | Meaning |
|---|---|
| `unrestricted_app_id` | `allowedAppIds` unset — any `appId` is accepted and silently creates a namespace. |
| `default_app_id` | `appId` left at `"ttc"` — no cross-app key isolation. |
| `no_requester_identity` | `trustProxyHeaders` false — the per-IP limit is skipped, so abuse controls fall back to keying on caller-supplied identifiers. |

## License

MIT
