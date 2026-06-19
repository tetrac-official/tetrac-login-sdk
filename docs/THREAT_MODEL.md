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
| Session bearer token | `localStorage` (client), KV (server) | High — grants authenticated access |
| `authPublicKey`, public keys, email, encrypted wallet blobs | Server KV | Low–Medium (public/ciphertext) |

---

## 2. Trust boundaries & actors

- **Client (browser):** runs untrusted alongside the host page's other scripts. Assumed honest-but-fragile
  — an XSS or malicious extension is a realistic threat.
- **Server (Next.js + KV/Redis):** trusted to store records and enforce challenge/session/rate-limit
  rules, but is **never** given plaintext keys, passkeys, or the app key.
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
6. **Production storage:** a persistent KV/Redis (not the in-memory adapter), and TLS everywhere.
7. **Choose `securityLevel`** appropriate to your latency budget (default 2 = 600k).

---

## 6. Out of scope (by design)

- **Server-side EVM/secp256k1 signature verification** — external wallet login is **Solana-only**; EVM
  keys are internal client-generated signing wallets.
- **Key escrow / custodial recovery** — would break the non-custodial guarantee.
- **Legacy/unauthenticated ciphertext or sub-OWASP KDF defaults** — not supported.

> Changes to this model ship with the release that changes the code. For the current open hardening items
> (WI-15 hardware WebAuthn assertion, WI-16 HKDF enc/auth separation, others), see
> [`audits/v0.3.2-PRD.md`](../audits/v0.3.2-PRD.md).
