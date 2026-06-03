# PRD — `@tetrac/login-sdk`

A reusable, framework-agnostic authentication SDK that packages the auth system currently
living inside `next-ttc` so any project can drop in email, Web3 wallet, and passkey/biometric
login with **client-side, non-custodial wallet generation** built in.

- **Status:** Draft v1
- **Author:** TTC Engineering
- **Date:** 2026-06-03
- **Source system:** `TTC/next-ttc` (the reference implementation this SDK is extracted from)
- **Target package:** `TTC/ttc-login-sdk`

---

## 1. Problem & Motivation

The `next-ttc` trading platform contains a mature, production-grade, crypto-native auth stack:
three login methods, deterministic key derivation, encrypted-at-rest wallets, WebAuthn PRF, and a
Redis/Vercel-KV storage layer. Today this logic is **tangled into the app** — spread across
`src/utils/authUtils.ts`, `src/services/PasskeyService.ts`, `src/lib/db.ts`, and ~8 API routes.

Other TTC projects (`tg-ttc-api`, `ttc-ai-bot`, future dApps) need the same authentication but
currently can't reuse it without copy-pasting. We want to extract this into a versioned,
installable SDK with clean boundaries so:

- New projects integrate auth in hours, not weeks.
- Security fixes ship once and propagate via a version bump.
- The wallet-generation + encryption model stays consistent across the whole TTC ecosystem.

### Goals

1. Package all three auth flows (email/passkey, Web3 wallet, biometric/WebAuthn) as importable modules.
2. Ship **client-side wallet generation** (Solana + EVM) as a first-class SDK feature — keys are
   created in the browser, encrypted before they ever leave the device, never custodial.
3. Provide a pluggable storage adapter: local Redis (`ioredis`) for dev, Upstash/Vercel KV for prod.
4. Be framework-agnostic at the core, with thin Next.js (App Router) and React bindings on top.
5. Preserve the existing security model: deterministic key recovery, encryption keys never in
   `localStorage`, rate limiting, replay-resistant challenges.

### Non-Goals (v1)

- Replacing `next-auth`/OAuth social logins (Google, GitHub) — out of scope for v1.
- Server-side custodial key storage or MPC/threshold wallets.
- Account abstraction / smart-contract wallets (4337).
- Migrating `next-ttc` to consume the SDK — that is a **follow-up** project; v1 only ships the SDK.
- UI theming system beyond unstyled/headless components + the existing TTC popups as examples.

---

## 2. Users & Use Cases

| Consumer | Use case |
|---|---|
| TTC dApp developers | Add login + auto-generated trading wallets to a new Next.js app |
| `tg-ttc-api` / bot backends | Verify SDK-issued session tokens server-side |
| External/partner projects | Embed TTC-compatible non-custodial wallet auth |

Primary end-user flows the SDK must support:

1. **Email + passkey** sign-up/login → app key derived deterministically (PBKDF2), wallets generated client-side.
2. **Web3 wallet** login (Phantom/Solana adapter) → challenge → signature verify → app key from signature.
3. **Biometric** (Touch ID / Face ID via WebAuthn, PRF + gate fallback) → unlock stored credentials.

---

## 3. Existing Implementation (Reference Inventory)

This is what the SDK is extracted from. File paths are in `next-ttc`.

### Auth methods
- **Email/passkey:** `src/utils/authUtils.ts` (`fetchEmailLogin`), `src/app/api/auth/login/route.ts`.
  Passkey SHA-256 hashed client-side; app key via `deriveApiKeyFromPasskey(passkey, email)` (PBKDF2, 100k iters).
- **Web3 wallet:** `src/utils/authUtils.ts` (`handleWalletLogin`), routes `challenge` + `login-wallet`.
  Challenge (32 random bytes, 5-min TTL), signature verified with `tweetnacl` `nacl.sign.detached.verify`.
- **Biometric/WebAuthn:** `src/services/PasskeyService.ts`, `src/services/PasskeySession.ts`.
  PRF mode (key derived from Secure Enclave, never stored) + gate mode (non-extractable AES-GCM key in IndexedDB).

### Wallet generation (client-side)
- **Solana:** `src/utils/clientWalletGenerator.ts` — `Keypair.generate()` (`@solana/web3.js`).
  Two keypairs: a **funds** wallet and a **signing/agent** wallet.
- **EVM:** `src/utils/exchange/vestUtils.ts` — currently `ethers.Wallet.createRandom()`; the SDK
  standardizes on **viem** (`generatePrivateKey()` / `privateKeyToAccount()`). Two keypairs: funds + signing/agent.
- All secret keys encrypted with `crypto-es` AES under the derived app key **before** transmission.

### Sessions & keys
- Session token: `crypto.randomBytes(32).toString("hex")`, stored `localStorage: ttc-auth-token`, sent via `ttc-auth-token` header.
- App/encryption key: in-memory + `sessionStorage: ttc_ek` only — **never** `localStorage`.
- Status model: `authenticated | session_expired | unauthenticated` (`getAuthStatus()`).

### Storage
- `src/lib/db.ts` switches on `process.env.VERCEL`: `@vercel/kv` (prod) vs `ioredis` (dev).
- Keys: `challenge:{pubKey}` (300s TTL), `pubKey:{pubKey}` (UserData), `email:{email}` (→ pubKey), rate-limit keys.
- Rate limiting: `src/lib/rateLimit.ts`, dual-key (IP + email).

### Dependencies (versions in source)
`@solana/web3.js` 1.98.4 · `viem` 2.46.1 (SDK standardizes on this for EVM, dropping `ethers`) ·
`tweetnacl` 1.0.3 · `crypto-es` 2.1.0 · `@vercel/kv` 3.0.0 · `ioredis` 5.6.1 · `@solana/wallet-adapter-*`.
No `next-auth`, no `jose`, no `@simplewebauthn` — custom WebAuthn is kept (see §5). Next.js 16, App Router, React 18, TS 5.8.

---

## 4. SDK Architecture

Monorepo-style single package with layered, tree-shakeable subpath exports. Core is framework-agnostic;
adapters and React/Next bindings are optional.

```
@tetrac/login-sdk
├── /core        → framework-agnostic auth logic, crypto, key derivation, wallet gen
│                  (no React, no Next, no DOM-API assumptions beyond WebCrypto/WebAuthn)
├── /client      → browser-only: wallet generation, encryption, WebAuthn, session storage
├── /server      → server-only: challenge issue/verify, signature verify, session issue,
│                  route handler factories, token validation
├── /storage     → StorageAdapter interface + RedisAdapter (ioredis) + KVAdapter (@vercel/kv)
│                  + UpstashAdapter (@upstash/redis)
├── /react       → hooks (useAuth, useWallet, useAuthState) + headless components
└── /next        → App Router route-handler factory, middleware helper
```

### Subpath exports
```ts
import { deriveAppKey, encryptSecret } from "@tetrac/login-sdk/core";
import { generateSolanaWallet, generateEvmWallet, registerPasskey } from "@tetrac/login-sdk/client";
import { createAuthRouteHandlers, verifySession } from "@tetrac/login-sdk/server";
import { RedisAdapter, VercelKVAdapter, UpstashAdapter } from "@tetrac/login-sdk/storage";
import { useAuth, AuthProvider } from "@tetrac/login-sdk/react";
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
```

### Design principles
- **Crypto libs are peer dependencies** (`@solana/web3.js`, `ethers`, `tweetnacl`) so consumers
  don't get duplicate copies that bloat bundles or cause version skew.
- **No secret ever leaves the browser unencrypted.** The server only sees ciphertext + public keys + hashes.
- **Storage is injected**, never imported transitively into the client bundle.
- **Stable, documented config object** so behavior (PBKDF2 iters, TTLs, header names, key prefixes)
  is configurable but defaults match `next-ttc` exactly for drop-in compatibility.

---

## 5. Client-Side Wallet Generation (first-class feature)

This is an explicit requirement and a headline SDK capability.

### Wallet roles
Every wallet is generated under a **role** so consumers ask only for what they need. Two standard roles per chain:

- **`funds`** — holds assets / receives deposits. The user's primary wallet on that chain.
- **`signing`** — the **agent wallet**: signs transactions and delegated actions (e.g. EIP-712, trade
  authorization) without exposing the funds key. Can be authorized/revoked independently.

TTC requests both roles on both chains (= the four keypairs today: Solana funds + Solana signing,
EVM funds + EVM signing). A lightweight consumer can request `{ solana: ['funds'] }` and get exactly one.

### Requirements
- Generate **Solana** keypairs in-browser via `@solana/web3.js` `Keypair.generate()`.
- Generate **EVM** keypairs in-browser via `viem` `generatePrivateKey()` → `privateKeyToAccount()`.
- Generic, role-based API — no chain/role hardcoded; consumer declares the set.
- Encrypt every secret key with `crypto-es` AES under the derived app key **before** any network call.
- Return a typed `GeneratedWalletBundle` keyed by chain → role, each with public key/address (plaintext)
  + encrypted secret blob.
- Provide decrypt-to-sign helpers that decrypt only for the signing operation, then zero/discard
  (preserve the existing `AUTO_LOCK_MS` 15s pattern from `secureKeyAccess.ts`).

### Proposed API
```ts
const bundle = await generateWalletBundle({
  appKey,                              // derived from passkey+email OR wallet signature
  solana: ["funds", "signing"],        // ask for the roles you need
  evm:    ["funds", "signing"],
});
// bundle.solana.funds.publicKey      bundle.solana.signing.publicKey
// bundle.evm.funds.address           bundle.evm.signing.address
// each role also carries .encryptedSecret (ciphertext only)

const signed = await withDecryptedKey(bundle.evm.signing, appKey, async (secretKey) => {
  return signTypedData(payload, secretKey);   // key auto-zeroed after callback
});
```

### Security constraints
- Encryption key (app key) lives in memory + `sessionStorage` only; never `localStorage`, never sent to server.
- Deterministic recovery: same passkey+email (or same wallet signature) re-derives the app key, so a
  user can decrypt their wallets on any device without the server ever holding the key.
- Decrypted secrets held as zeroable `Uint8Array` where the host runtime allows.

---

## 6. Storage Adapter

```ts
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: { exSeconds?: number }): Promise<void>;
  del(key: string): Promise<void>;
  incr(key: string): Promise<number>;        // for rate limiting
  expire(key: string, seconds: number): Promise<void>;
}
```

- `RedisAdapter(ioredis)` — dev, localhost:6379.
- `VercelKVAdapter(@vercel/kv)` — Vercel production.
- `UpstashAdapter(@upstash/redis)` — Upstash REST (edge-friendly, explicitly requested).
- Auto-select helper: `resolveStorageAdapter()` mirrors `db.ts` (`process.env.VERCEL` / Upstash env vars present).

Configurable key namespace prefix (default matches `next-ttc`: `challenge:`, `pubKey:`, `email:`).

---

## 7. Server API Surface

Route-handler factory produces the endpoints currently hand-written in `next-ttc`:

| Endpoint | Purpose |
|---|---|
| `POST /auth/challenge` | Issue 32-byte challenge, store `challenge:{pubKey}` TTL 300s, rate-limited |
| `POST /auth/register` | Validate client-generated wallets, store encrypted blobs + email→pubKey map, issue token |
| `POST /auth/login` | Email/passkey: resolve pubKey, verify hashed passkey, return UserData + token |
| `POST /auth/login-wallet` | Verify nacl signature against challenge, derive nothing server-side, issue token |
| `GET /auth/user-data` | Authenticated: return encrypted wallet blobs |
| `GET /auth/search-wallet` | Existence check by public key |
| `POST /auth/import-wallet` | Import an existing external wallet |

```ts
// next-ttc consumer example
export const { POST } = createNextAuthRoutes({
  storage: resolveStorageAdapter(),
  config: { pbkdf2Iterations: 100_000, challengeTtlSeconds: 300, sessionHeader: "ttc-auth-token" },
});
```

Plus `verifySession(req, storage)` for any backend to validate the `ttc-auth-token` header.

---

## 8. React / Next Bindings

```tsx
<AuthProvider config={...} apiBaseUrl="/api/auth">
  <App />
</AuthProvider>

const { status, user, loginWithEmail, loginWithWallet, loginWithBiometric, logout } = useAuth();
```

- `useAuth()` — exposes the `authenticated | session_expired | unauthenticated` status model + actions.
- `useWallet()` — access generated wallet bundle + decrypt-to-sign helpers.
- Headless components (`<LoginGate>`, `<RegisterFlow>`, `<PasskeyPrompt>`) port the existing TTC popups
  as styling-agnostic primitives; the current branded versions ship as examples.

---

## 9. Configuration & Environment

```
# dev
REDIS_URL=redis://localhost:6379

# production (one of)
VERCEL=1                          # uses @vercel/kv
KV_REST_API_URL=...               # Upstash / Vercel KV REST
KV_REST_API_TOKEN=...
UPSTASH_REDIS_REST_URL=...
UPSTASH_REDIS_REST_TOKEN=...
```

`AuthConfig` (typed, all optional with `next-ttc` defaults):
`pbkdf2Iterations`, `challengeTtlSeconds`, `sessionHeader`, `publicKeyHeader`, `keyPrefixes`,
`rateLimit { windowSeconds, maxAttempts }`, `webauthn { rpId, rpName, preferPrf }`.

---

## 10. Security Requirements (carried over, must not regress)

1. Private keys encrypted at rest (AES); plaintext secrets never persisted.
2. Encryption/app key: memory + `sessionStorage` only, never `localStorage`, never transmitted.
3. Deterministic app-key recovery (PBKDF2 from passkey+email; SHA-256 of wallet signature).
4. WebAuthn `userVerification` required; PRF preferred, gate-mode fallback.
5. Challenge 5-min TTL + single-use → replay resistance.
6. Dual-key (IP + identifier) rate limiting on all auth routes.
7. Decrypt-to-sign with auto-lock (~15s) and key zeroing.
8. Server sees only: public keys, ciphertext blobs, SHA-256 passkey hash, signatures.

---

## 11. Distribution & Tooling

- **Package name:** `@tetrac/login-sdk`, published **publicly to npmjs**; source in its own **GitHub repo**
  (separate git history from `next-ttc`). GitHub Actions runs CI and `npm publish` on tag.
- **Build:** `tsup` → ESM + CJS + `.d.ts`, per-subpath entry points, `sideEffects: false` for tree-shaking.
- **Peer deps:** `@solana/web3.js`, `viem`, `tweetnacl`, `react`, `next` (the last two optional/peer-marked).
  `ethers` is **not** a dependency — EVM uses viem.
- **Bundled/own deps:** `crypto-es`, the custom WebAuthn helpers (ported from `PasskeyService.ts`).
- **Tests:** Jest (matches `next-ttc`) — crypto round-trips, signature verify, key derivation determinism,
  storage adapters against a real localhost Redis + mocked KV.
- **TS:** 5.8, strict.
- **Versioning:** semver; changeset-driven changelog.

---

## 12. Milestones

| Phase | Deliverable |
|---|---|
| **M0 — Scaffold** | Package, build pipeline, subpath exports, CI, empty typed surfaces |
| **M1 — Core crypto + wallet gen** | `core` + `client`: key derivation, AES encrypt/decrypt, Solana/EVM generation, decrypt-to-sign. Unit-tested. |
| **M2 — Storage adapters** | Redis / Vercel KV / Upstash adapters behind `StorageAdapter`, auto-resolve |
| **M3 — Server** | Route-handler factory for all endpoints, challenge/signature/session, rate limiting, `verifySession` |
| **M4 — WebAuthn/biometric** | PRF + gate modes, IndexedDB credential store, registration + re-login |
| **M5 — React/Next bindings** | `AuthProvider`, `useAuth`/`useWallet`, headless components, Next route factory |
| **M6 — Docs + example app** | README, API docs, runnable example wiring all three flows |
| **M7 (follow-up)** | Migrate `next-ttc` to consume the SDK; deprecate in-app copies |

---

## 13. Acceptance Criteria

- A fresh Next.js 16 App Router app can install the SDK and wire all three login flows in < 1 hour
  following the README, using localhost Redis in dev and Upstash/Vercel KV in prod via env vars only.
- Wallets are generated client-side and the server bundle contains zero plaintext secret keys
  (verifiable in the example app's network tab).
- A user who registers with email+passkey on one device can log in and decrypt the same wallets on
  a second device with no server-side key storage.
- Web3 wallet login completes a challenge→sign→verify round trip with `tweetnacl` verification.
- Biometric re-login works via Touch ID/Face ID (PRF where supported, gate fallback otherwise).
- Security checklist in §10 fully satisfied; no regression vs `next-ttc`.

---

## 14. Decisions & Open Questions

### Decided
1. **Distribution:** public npmjs package `@tetrac/login-sdk`, own GitHub repo, publish via GitHub Actions on tag.
2. **EVM lib:** **viem** (`generatePrivateKey` / `privateKeyToAccount`). `ethers` dropped from the SDK.
3. **WebAuthn:** **keep the custom implementation** (ported from `PasskeyService.ts`). `@simplewebauthn`
   rejected for v1 — it centers on standard auth ceremonies, whereas our model needs the **PRF extension**
   to derive the wallet-encryption key from the Secure Enclave. May borrow `@simplewebauthn/server`
   verification helpers later, but not required.
4. **Wallet bundle:** **generic, role-based API.** Two standard roles per chain — `funds` (holds assets)
   and `signing` (agent wallet for delegated signing). Consumers request the set they need; TTC requests
   both roles on Solana + EVM.

### Still open
5. **Session backend:** keep opaque random tokens in KV, or offer an optional stateless JWT (`jose`) mode?
6. **Telegram login:** `next-ttc` has `telegram-login`; include in v1 or defer?
7. **npm scope name:** `@ttc` vs `@tradingtoolcrypto` — which org/scope to register on npmjs?
