# Threat Model — `@tetrac/login-sdk`

What the SDK protects, who it protects against, what it stops in library code, and what it **cannot** stop
(and therefore delegates to the integrator). Pairs with [`docs/CRYPTO_SPEC.md`](./CRYPTO_SPEC.md).

---

## 1. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Wallet private keys | Generated in-browser; stored only as AES-256-GCM ciphertext (client + server) | **Critical** — controls funds |
| App / encryption key | Browser **memory only**; derived per session | **Critical** — decrypts all wallets |
| Passkey / wallet signature (the KDF input) | Authenticator / wallet; never persisted by the SDK | **Critical** |
| Session bearer token | `localStorage` (client) **only**. The server stores just **SHA-256(token)** (v0.5.0) — never the token | High — grants authenticated access |
| `authPublicKey`, public keys, email, encrypted wallet blobs | Server store | Low–Medium (public/ciphertext) — but see **R9**: the blobs are an offline-cracking corpus |

---

## 2. Trust boundaries & actors

- **Client (browser):** runs untrusted alongside the host page's other scripts. Assumed honest-but-fragile
  — an XSS or malicious extension is a realistic threat.
- **Server (Next.js + a conformant storage backend):** trusted to store records and enforce
  challenge/session/rate-limit rules, but is **never** given plaintext keys, passkeys, the app key,
  or (since v0.5.0) the raw session token.
- **The storage backend itself is a trust boundary, not an implementation detail** (v0.5.0). It may
  be Redis, Postgres/Supabase, Mongo, or a bring-your-own `AuthStore` — and it may be backed up,
  replicated, logged, or (on Supabase) served to the public internet by default. The SDK therefore
  assumes the store **can** be read by an adversary and minimizes what a read is worth: no raw
  tokens, no plaintext keys. See **R8/R9** and [`STORAGE_ADAPTERS.md`](STORAGE_ADAPTERS.md).
- **Authenticator / wallet:** the root of trust for a user. Possession + user verification is the factor.
- **Network:** assumed hostile (use TLS); the SDK additionally never transmits secrets.

Adversaries considered: a passive/active network attacker; a malicious or compromised relying site; an
attacker who exfiltrates the **server** database; an attacker who achieves **XSS** on the client; an
offline brute-forcer of stolen ciphertext; a replay/credential-stuffing attacker.

---

## 3. Threats and mitigations (in library code)

| # | Threat | Mitigation | Reference |
|---|---|---|---|
| T1 | **Server DB leak** exposes wallets | Keys stored only as **AES-256-GCM** ciphertext; app key never on the server | CRYPTO_SPEC §3 |
| T2 | **Ciphertext tampering / malleability** | AEAD (GCM tag) — decrypt **throws** on any tamper; no CBC, no unauthenticated path | `crypto.ts:80-93` |
| T3 | **Offline brute-force** of stolen ciphertext | PBKDF2-HMAC-SHA256 @ **600k** default, per-user pinned; Web3/biometric keys are high-entropy | CRYPTO_SPEC §2 |
| T4 | **Cross-app key reuse** (key cracked on app A unlocks app B) | `appId` domain-separates the PBKDF2 salt and the wallet sign-message | CRYPTO_SPEC §2.1/§2.2 |
| T5 | **Passkey-hash theft from server** | Server stores **no** passkey hash — only an ed25519 `authPublicKey`; auth is challenge–signature | CRYPTO_SPEC §5.1 |
| T6 | **Challenge replay / signature reuse** | 256-bit single-use challenge, **atomic `getdel`**, 5-min TTL, `timingSafeEqual` compare | `challenge.ts` |
| T7 | **Stolen/long-lived session token** | Opaque 256-bit CSPRNG token, 4h TTL, **single active session** (login revokes prior), `logout` revokes | `session.ts` |
| T7b | **Server DB leak yields *live, replayable* session tokens** | **v0.5.0:** the store holds only **SHA-256(token)** — as the session key *and* in the user record. The raw token is a bearer credential that exists only in the client's hands. A dumped table, backup, replica, or query log therefore yields **digests, not credentials**. The token is 256 bits of CSPRNG output, so a bare hash is preimage-secure with no KDF (the API-key construction). *Before v0.5.0 the raw token was stored in **both** places, so read access to the store was equivalent to account takeover for every logged-in user.* | `crypto.ts` `hashSessionToken`, `session.ts` |
| T8 | **Key-at-rest theft via storage-scraping XSS** | App key is **memory-only**; auto-lock (idle/hide/freeze/bfcache) + cross-tab lock | CRYPTO_SPEC §6 |
| T9 | **Silent signing-window extension on reveal** | `revealSecret()` uses a one-time key and does **not** arm the session | `authClient.ts:149-162` |
| T10 | **Rate-limit evasion via spoofed `X-Forwarded-For`** | XFF ignored unless `trustProxyHeaders`; per-target buckets; rightmost-after-`trustedProxyHops` | `http.ts:25-37` |
| T11 | **Weak RNG / silent crypto downgrade** | `getRandomValues` required (throws if absent); **no** `Math.random` fallback; Web Crypto only | `crypto.ts:96-106` |
| T12 | **Crypto-state / user-enumeration oracle on login** | Generic `Invalid credentials` 401; generic decrypt error | `routes.ts`, `crypto.ts:91` |
| T13 | **Biometric secret read at rest** | PRF secret never stored; gate secret under a **non-extractable** AES-GCM key, released only after UV | `webauthn.ts:200-247` |
| T14 | **Supply-chain surface of a heavy crypto dep** | `crypto-es` removed; single runtime dep `@noble/hashes` (audited) + Web Crypto | `package.json` |

---

## 4. Residual & accepted risks (NOT fully fixable in library code)

These are inherent to a **non-custodial, client-side** SDK. They are accepted in code and delegated to the
integrator (see §5).

| # | Residual risk | Why the SDK can't fully close it |
|---|---|---|
| R1 | **XSS can act as the user while a tab is unlocked** | A token in `localStorage` must be page-readable; an unlocked vault can sign. Memory-only + auto-lock limits the window, not the capability. |
| R2 | **Total factor loss = unrecoverable funds** | Non-custodial by definition — there is no escrow/recovery to fall back on. |
| R3 | **`/challenge` account enumeration** | A real login needs a challenge for known accounts; one can't be issued for unknown — structural. |
| R4 | **Login work-amplification / volumetric floods** | Verify-first does cheap work before the failure counter trips; needs edge/volumetric limiting. |
| R5 | **No proof of email ownership at register** | The SDK sends no email and can't verify control of an address. |
| R6 | **Biometric not yet bound to a hardware WebAuthn assertion** | Current biometric auth verifies a client-derived signature, not `origin`/`rpIdHash`/`signCount`. **Tracked: WI-15.** |
| R7 | **Phishing / malicious relying site** | A site the user trusts can prompt signatures. `appId` binding limits cross-app key reuse but not in-app abuse. |
| R8 | **Storage-layer misconfiguration exposes the auth store** | New in v0.5.0, and a **first-class trust boundary** now that the store may be a real database. The SDK cannot police the operator's database: a world-readable Supabase `public` schema, a leaked backup, a read replica, an analytics sync, a slow-query log, or a SQLite file under `public/` all expose the auth tables. **What v0.5.0 changes:** session tokens are now stored as **SHA-256 digests** (see below), so such a read no longer yields replayable credentials. See §5.6 and [`STORAGE_ADAPTERS.md`](STORAGE_ADAPTERS.md). |
| R9 | **A leaked store is still an offline-cracking corpus** | Hashing the session token does **not** address this. The store holds every user's **encrypted wallet blob**. Those are client-side-encrypted (AES-256-GCM behind PBKDF2 at the configured `securityLevel`, default 600k), so an attacker gets ciphertext and must go offline — but a weak user passkey is then crackable at their leisure. Only key strength stands between a dumped table and the funds. |

---

## 5. Integrator obligations

The SDK is secure **only when deployed correctly.** You are responsible for:

1. **Strict CSP + Trusted Types + SRI** to minimize XSS (mitigates R1). Keep `autoLockMs` short.
2. **Email verification (magic link / OTP) and bot-gating (CAPTCHA / Turnstile)** before register
   (mitigates R5/R3).
3. **Edge / volumetric rate limiting** in front of the app (mitigates R4); set `trustProxyHeaders` /
   `trustedProxyHops` only behind a proxy you control.
4. **A unique, stable `appId`** per deployment — the default `"ttc"` gives no cross-app isolation
   (mitigates T4).
5. **Backup-factor UX:** prompt users to register a second authenticator and warn about R2.
6. **Production storage:** a persistent, durable, **conformant** backend — never the in-memory
   adapter. Since v0.5.0 the store is a first-class trust boundary (R8), so:
   - **Verify your backend against the conformance suite** (`@tetrac/login-sdk/storage/conformance`).
     A backend that looks correct and is not will permanently lock users out, accept expired
     sessions, or replay login challenges. This is the acceptance bar, not a formality.
   - **TLS that actually authenticates the server.** `sslmode=require` **does not verify the
     certificate** — it encrypts and accepts *any* cert, so it stops passive sniffing and does
     nothing against an active MITM. Use **`sslmode=verify-full`** (Postgres) / `tls=true` with no
     `tlsAllowInvalidCertificates` (Mongo).
   - **Least privilege.** A dedicated DML-only database role. On Supabase, put the tables in a
     **non-`public` schema** — the `public` schema is served over PostgREST to anyone holding the
     browser-shipped `anon` key — and never connect as `service_role`.
   - **Assume the store may leak** (backup, replica, log, misconfigured schema) and plan for R9.
7. **Choose `securityLevel`** appropriate to your latency budget (default 2 = 600k). Since a dumped
   store is an offline-cracking corpus (R9), this is the parameter that decides how long the wallet
   ciphertext holds.

---

## 6. Out of scope (by design)

- **Server-side EVM/secp256k1 signature verification** — external wallet login is **Solana-only**; EVM
  keys are internal client-generated signing wallets.
- **Key escrow / custodial recovery** — would break the non-custodial guarantee.
- **Legacy/unauthenticated ciphertext or sub-OWASP KDF defaults** — not supported.

> Changes to this model ship with the release that changes the code. For the current open hardening items
> (WI-15 hardware WebAuthn assertion, WI-16 HKDF enc/auth separation, others), see
> [`audits/v0.3.2-PRD.md`](../audits/v0.3.2-PRD.md).
