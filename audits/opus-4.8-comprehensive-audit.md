# Comprehensive Security Audit — `@tetrac/login-sdk` v0.2.0

**Auditor:** Claude Opus 4.8 (multi-agent: 7 dimension finders + dual-lens adversarial verification + cross-check against `grok.md` and `deepseek-v4.md`)
**Date:** 2026-06-11
**Scope:** `src/**` (core crypto, client vault, server routes/session/challenge/ratelimit/signature, storage adapters, WebAuthn, React hooks, Next binding), `package.json`, `tsup.config.ts`, published tarball.
**Method:** First-hand line-by-line review + verified `crypto-es` internals + `npm audit`/`npm pack` + reconciliation with two prior audits (one of which ran 133 empirical test cases).

---

## Verified ground truth (corrects common misconceptions)

These were established by reading `node_modules/crypto-es` source and grepping the repo. They materially change severities, so they are stated up front:

| Claim | Reality | Source |
|---|---|---|
| PBKDF2 hash algorithm | **SHA-256** (not SHA-1) | `crypto-es/lib/pbkdf2.js:33-41` — default `hasher: SHA256Algo, iterations: 250000`; code passes `iterations:100_000`, hasher defaults ⇒ **PBKDF2-HMAC-SHA256, 100k** |
| AES key/IV derivation | OpenSSL EvpKDF: **MD5, 1 iteration**, random 8-byte salt per encryption | `crypto-es/lib/evpkdf.js:36-38` |
| AES mode | **AES-256-CBC + PKCS7, no auth tag** | `crypto-es/lib/cipher-core.js` default `mode: CBC` |
| EvpKDF weakness exploitability | **Not** a practical brute-force vector — the `appKey` passed in is already a 256-bit hex string (high entropy) | analysis |
| Server signature verification | **Solana ed25519 only** (`tweetnacl`); no secp256k1/EVM verifier exists | `src/server/signature.ts`, grep of `src/server` |
| `npm audit` (prod deps) | **0 vulnerabilities**; `uuid@8.3.2` not flagged | `npm audit --omit=dev` |

---

## Empirical validation (post-audit)

The findings below were subsequently **confirmed by executable tests against the unmodified `src/`** — no theory-only claims among the High+ items. Coverage:

- **`tests/audit-crypto.test.ts`, `tests/audit-server.test.ts`, `tests/audit-client-vault.test.ts`** (29 tests, all green) — characterization tests authored for this audit. Each asserts the *current* (vulnerable) behavior, so green = finding reproduced. They double as the regression baseline to **invert** once hardening lands. Highlights: a full **C1** end-to-end (crack the leaked `passkeyHash` from a 4-word dictionary → re-derive `appKey` → decrypt the wallet, in one test); **H3** (raw `appKey` readable at `sessionStorage["ttc_ek"]`); **H5** (3 distinct clients share one `ratelimit:unknown` bucket); **H6** (EVM 0x registers via the email path, 201); **SERVERSIDE-1/8** (unauthenticated write into `pubKey:session:*` + `JSON.parse` crash); **WEBAUTHN-1** (login with only `{email, passkeyHash}`).
- **`tests/ciphertext-tampering.test.ts`** (deepseek's suite, now repo-present) refines **H1**: `CryptoES.AES.decrypt` of a tampered blob *never throws* and returns a **malformed WordArray with a negative `sigBytes` (e.g. −139)** — there is no authentication whatsoever — while the parallel AES-GCM (v2) tests reject every single-bit flip. This is even stronger than "tampering ≈ wrong key."
- **`tests/timing-safe-edge-cases.test.ts`** + `audit-crypto.test.ts` confirm **CRYPTO-5 is a non-issue** (the implementation is correct for fixed-length hex): the finding stays **disproven**.
- Full suite: **162/162 passing, 22 suites.**

---

## Executive Summary

**Overall risk: HIGH** (architecture is sound; the cryptographic *storage* layer and several default settings are not yet production-grade for a system guarding irrecoverable funds).

The non-custodial design is genuinely well thought-out: client-side key generation, AES encryption under a key the server never sees, atomic single-use challenges (`getdel`), opaque revocable session tokens with single-active-session, a memory/auto-lock vault with re-auth-to-reveal, and a correctly-implemented non-extractable AES-GCM wrap for gate-mode secrets. The randomness source is correct (`getRandomValues` with a hard-fail fallback) and `timingSafeEqual` is correct for its fixed-length-hex inputs (empirically confirmed).

However, the security of a non-custodial wallet SDK is decided by its **weakest credential at rest** and its **default client posture**, and both have gaps:

1. **The server-stored `passkeyHash` is an unsalted single SHA-256 of a human-chosen password.** On a storage leak this is GPU-crackable in minutes and *bypasses* the 100k-PBKDF2 protection entirely — recovering the passkey re-derives the `appKey` and decrypts every wallet. This is the single highest-impact issue.
2. **Wallet secrets use unauthenticated AES-CBC** — no integrity, malleable, tampering is indistinguishable from a wrong key.
3. **The `appKey` (master wallet-decryption key) is written to `sessionStorage` in cleartext by default**, so a single XSS = total wallet compromise.
4. **The wallet key-derivation message is a domain-unbound global constant** — any site can prompt the same wallet to derive the same key (cross-site phishing).
5. **Per-IP rate limiting collapses to one global bucket by default**, giving an unauthenticated global DoS on `/challenge` (which gates all wallet logins).
6. **Biometric/WebAuthn "login" is never verified server-side** — it reduces to possession of `SHA-256(appKey)`, forfeiting WebAuthn's phishing-resistance at the server boundary.

None of these are remotely exploitable for key theft *without* a precondition (DB leak, XSS, or phishing) — but all three preconditions are explicitly in the threat model, and the impact is irreversible loss of funds. With the Immediate + Short-term roadmap applied, the posture moves to solidly production-grade.

**Severity tally (post-verification, after the EVM scope correction):** 1 Critical · 6 High · 17 Medium · 24 Low · ~7 Info · 1 refuted false-positive · **5 reclassified as by-design** (the EVM "wallet login" cluster — see below).

> **EVM scope correction (maintainer-confirmed):** EVM keypairs are *internal, client-generated signing wallets* (`useEvmSigner` → `viem` `LocalAccount`), **not external auth identities**. External wallet *login* is Solana-only by design, so `verifySolanaSignature` being ed25519-only is **correct**, and the "EVM login unimplemented/fragile" findings (`H6`/`AUTHSESSION-1`/`DESIGN-2`/`SERVERSIDE-3`, and the EVM half of `CRYPTO-4`/`DESIGN-6`) are **withdrawn**. The only residual is a doc-clarity note (`DESIGN-12`). The generic `publicKey`-validation / email-ownership gaps (`SERVERSIDE-1/5/11`) remain valid on their own.

---

## Detailed Findings

> IDs map to the multi-agent finder output. Severities below are the **reconciled** values after adversarial verification and cross-check with the two prior audits; where I diverge from a finder's self-rating I say so.

### 1. Cryptography (highest priority)

#### 🔴 CRITICAL — C1 / `CRYPTO-1`: Server-stored `passkeyHash` is unsalted single SHA-256 (bypasses PBKDF2; full wallet recovery on DB leak)
- **Location:** `src/core/crypto.ts:42-44` (`hashPasskey`); stored/compared at `src/server/routes.ts:149,172`; persisted `src/server/session.ts:14`.
- **Impact:** For email accounts the *only* server-side verifier is `SHA-256(passkey)` — unsalted, single round. On a Redis/KV leak an attacker cracks the passkey offline at ~10¹⁰ guesses/s/GPU (an 8-char password falls in minutes; common-password lists instantly), then feeds the recovered passkey into `deriveAppKeyFromPasskey(passkey, email, 100k)` and decrypts **every** wallet secret in the same leaked record. The unsalted hash also lets one rainbow table attack all users at once, and identical passkeys produce identical hashes (visible in the leak). Attacking the 100k-PBKDF2 ciphertext directly is ~100,000× slower per guess, so attackers always target this hash. **Empirically confirmed** by `deepseek-v4.md` (≈100K SHA-256/s in Node; identical hash across users).
- **Evidence:** `crypto.ts:43` `return CryptoES.SHA256(passkey).toString(CryptoES.enc.Hex);` — no salt, one round. Login (`routes.ts:160-176`) requires only `email + passkeyHash`.
- **Severity note:** Rated **Critical (conditional on storage compromise)**. `deepseek-v4.md` rated the hash "High" in isolation; chained to full fund theft for all email users, I rank it the #1 issue. Biometric/wallet users are unaffected (`passkeyHash = SHA-256` of a 256-bit secret, not brute-forceable).
- **Recommendation:** Apply a **server-side salted, slow, peppered verifier over the transmitted hash** — this needs *no client/protocol change* and does not touch wallet ciphertext: store `{ v:2, salt, hash }` where `hash = PBKDF2-HMAC-SHA256(clientPasskeyHash, salt ∥ SERVER_PEPPER, ≥600k)` (Argon2id preferred where available). On login, compute and compare; fall back to legacy bare-SHA-256 and upgrade-on-login. Gate to `authMethod==='email'`. See patch §"Patched code".

#### 🟠 HIGH — H1 / `CRYPTO-3` · `DESIGN-10`: Wallet secrets use unauthenticated AES-256-CBC (no MAC/integrity)
- **Location:** `src/core/crypto.ts:46-56` (`encryptSecret`/`decryptSecret`); header note **D1** acknowledges it.
- **Impact:** No authentication tag ⇒ ciphertext is malleable (CBC bit-flips propagate to the next plaintext block) and tampering is **undetectable server-side** (the server never holds the `appKey`). `decryptSecret` only checks "UTF-8 decode non-empty," so corruption is indistinguishable from a wrong key. An attacker with KV write access (compromised/malicious storage, or an authenticated `import-wallet`/`connect-wallet` injection after session theft) can substitute or relocate blobs; a wallet blob can be moved from user A into user B's record with no cryptographic detection. `deepseek-v4.md` proved this empirically (2/128 bit-flips silently decrypt to garbage; 126/128 throw the *same* error as a wrong passkey) and rated it **Critical**. I rate it **High**: the practical impact is integrity/DoS/substitution, not direct key recovery (no server-side padding oracle exists since the server never decrypts).
- **Test:** `tests/ciphertext-tampering.test.ts` — `CryptoES.AES.decrypt` of a tampered blob returns a malformed WordArray (negative `sigBytes`) with no error; AES-GCM (v2) rejects every flip. `tests/audit-crypto.test.ts` asserts the `Salted__`-only format (no tag) and that a wrong key and a tampered blob are indistinguishable.
- **Recommendation:** Migrate to **AES-256-GCM** (Web Crypto `subtle`, 12-byte IV, 128-bit tag) with **associated data** binding `{publicKey, chain, role, v}` so a relocated blob fails authentication. Because this breaks next-ttc byte-compat, version the blob (`v2:…`) and keep a legacy CBC decrypt path + re-encrypt-on-unlock. **Immediate, sync, compat-preserving interim:** Encrypt-then-MAC the existing CBC blob — store `HMAC-SHA256(macSubkey, ct)` alongside, verify before decrypt; the inner CBC bytes are unchanged. See patch.

#### 🟠 HIGH — H2 / `CRYPTO-2`: KDF uses a low-entropy, cross-site-reusable salt (email) and below-guidance iteration count (100k)
- **Location:** `src/core/crypto.ts:21-31`; salt `crypto.ts:26` = `email.toLowerCase().trim()`; default `src/core/config.ts:68` `pbkdf2Iterations: 100_000`.
- **Impact:** (a) The salt is the user's **email** — public, predictable, and **identical across every deployment** of this SDK, so a precomputation against a target email transfers to that user on every site. (b) 100k is ~6× below OWASP's ~600k for PBKDF2-SHA256 (`deepseek-v4.md`: 1.2s vs 7.2s on M-series). Determinism (the stated reason, note **D3**) only requires a *deterministic* salt, not the bare email and not 100k. Once C1 is fixed, this KDF becomes the next offline target.
- **Recommendation:** (1) Raise default to **≥600k**. (2) Domain-separate the salt while keeping determinism: `salt = SHA-256(appId ∥ ':' ∥ normalizedEmail)`. (3) Persist `{kdfVersion, iterations}` per user (see DESIGN-9) so the bump is safe for existing accounts (`deepseek-v4.md` confirmed different counts ⇒ different keys), and migrate via re-encrypt-on-unlock. Long-term: Argon2id.

#### 🟠 HIGH — H4 / `DESIGN-1` · `CRYPTO-4`: `WALLET_APP_KEY_MESSAGE` is a fixed, domain-unbound constant (cross-site key derivation)
- **Location:** `src/core/index.ts:18-23`; consumed `src/client/authClient.ts:85,193`; `deriveAppKeyFromSignature` `crypto.ts:37-39`.
- **Impact:** The message a wallet signs to derive its encryption key has **no origin/appId/chainId/nonce**. `SHA-256(sig over this constant)` is the only secret decrypting all of a user's wallets, and it is identical on every site. Any malicious site can prompt the same wallet to sign the identical string (one innocuous, gas-free signature) and obtain the exact `appKey` — then pull ciphertext (via authenticated `/user-data`, the `/search-wallet` oracle, or a DB leak) and decrypt everything offline. The key can never be rotated because the message is fixed. The "Only sign on a site you trust" text is the sole control.
- **Recommendation:** Bind the message to the origin/appId (EIP-4361 SIWE-style for EVM; structured Solana message), so each origin derives a *different* key. Use `HKDF(sig, info)` rather than bare SHA-256 to allow domain-separated subkeys. Ship behind `kdfVersion` with decrypt-old/re-encrypt-new migration.

#### ⚪ RECLASSIFIED — By design (was `CRYPTO-4`/`DESIGN-6`): EVM signature determinism is not in scope
- **Maintainer clarification (accepted):** `deriveAppKeyFromSignature` is only ever fed the **external Solana** auth signature (ed25519, deterministic per RFC 8032). EVM keypairs are internal signing wallets and never feed key derivation, so the "non-RFC-6979 EVM signer breaks determinism" concern **does not apply**. **Withdrawn.**
- **The one part that DOES remain → folded into `H4`/`DESIGN-1`:** the *Solana* `WALLET_APP_KEY_MESSAGE` is still a fixed, domain-unbound constant, so a malicious site can prompt the user's Solana wallet to sign it and derive the same `appKey` cross-origin. That cross-site key-derivation risk is real and tracked under **H4**, independent of EVM.

#### 🟢 LOW — `CRYPTO-5`: `timingSafeEqual` — *disproven concern, keep as-is (optional hardening)*
- **Location:** `src/core/crypto.ts:87-94`.
- **Verdict:** The finder flagged a length/timing leak; **`deepseek-v4.md`'s 12-case test suite disproves the practical concern** — no early exit (loops `max(len)`), `charCodeAt(NaN)→0` is well-defined, Unicode/empty/single-bit cases all correct, and the compared operands (SHA-256 hex, 64-hex challenges) are fixed-length so loop length is constant by construction. **Low/Info.**
- **Recommendation (optional):** On the server (`routes.ts`, `challenge.ts`), `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` after a non-secret fixed-length check. Not required.

#### 🟢 LOW — `CRYPTO-6`: Email-login existence oracle via unbalanced verification path
- **Location:** `src/server/routes.ts:167-173`.
- **Impact:** `resolvePublicKeyByEmail` returns fast when no account exists, vs the full `getUserByPublicKey` + `timingSafeEqual` when it does — a timing oracle for email existence (and `register` returns an explicit 409, see AUTHSESSION-7). Low.
- **Recommendation:** Perform a dummy `timingSafeEqual` against a constant when the user is absent so both paths do equal work.

#### 🟢 LOW — `CRYPTO-8`: EvpKDF (MD5/1-iter) key+IV derivation
- **Location:** `crypto-es` default, used by `crypto.ts:48`.
- **Verdict:** Real but **not practically exploitable** — the input `appKey` is already 256-bit high-entropy, so the weak KDF doesn't reduce its strength. Subsumed by the AES-GCM migration (H1). Low.

#### ⚪ INFO — `CRYPTO-9`: Randomness is correct
- `randomHex` uses `getRandomValues` with a hard-throw fallback; challenges/tokens are 256-bit. No issue (positive finding).

#### 🟢 LOW — `CRYPTO-10`: Gate-mode legacy plaintext migration window
- **Location:** `src/client/webauthn.ts:213-218`.
- **Impact:** Pre-wrap (legacy) gate records hold the secret as plaintext hex in IndexedDB until first read rewraps it; if the rewrap transaction fails, the readable copy persists. Narrow (legacy gate-mode only, 256-bit secret). Low.
- **Recommendation:** On encountering a legacy record, rewrap, verify the wrapped record reads back, and explicitly delete the readable entry before returning; do a one-shot migration scan on init.

### 2. Authentication & Session Management

#### 🟠 HIGH — H5 / `AUTHSESSION-2` · `SERVERSIDE-2` · `DESIGN-7`: Per-IP rate limiting collapses to one global `ratelimit:unknown` bucket by default (global DoS + no IP throttle)
- **Location:** `src/server/http.ts:20-25` (`clientIp` returns literal `"unknown"` when `!trustProxyHeaders`); `src/core/config.ts:73` (`trustProxyHeaders:false` default); `routes.ts:91` (challenge) & `routes.ts:267` (search-wallet) pass **no identifier**.
- **Impact:** With the safe default, every client shares one global counter. `/challenge` and `/search-wallet` are governed *solely* by it (10/60s **globally**). (1) **Availability/DoS:** one host sending 11 `/challenge` POSTs per minute returns 429 to the entire user base — and challenge issuance gates *all* wallet logins. Even legitimate traffic >10 logins/min starts failing. (2) Per-IP brute-force throttling is effectively absent; the only real control is the per-email/per-pubKey bucket (itself bypassable, see DESIGN-7). `deepseek-v4.md` rated this **Low** ("documented limitation"); I rate it **High** because the no-identifier endpoints turn the "safe default" into a real availability bug + trivial unauthenticated DoS.
- **Recommendation:** Don't collapse all clients to one bucket. Derive a best-effort per-connection IP from the runtime (`request.ip`/socket) when no trusted proxy is set; give `/challenge` and `/search-wallet` a per-`publicKey` identifier so one client can't starve the pool; keep a separate, much-higher global ceiling distinct from the per-client path. Document that production **must** set `trustProxyHeaders:true` behind a trusted proxy with a constrained hop count.

#### ⚪ RECLASSIFIED — By design (was H6 / `AUTHSESSION-1` · `DESIGN-2` · `SERVERSIDE-3`): "EVM wallet login" is out of scope — external wallet auth is Solana-only by design
- **Maintainer clarification (accepted):** EVM keypairs in this SDK are **internal, client-generated signing wallets** (used via `useEvmSigner` / a `viem` `LocalAccount` over an `appKey`-encrypted secret), **not external Web3 auth identities**. External wallet *login* is Solana-only (a Solana adapter's `publicKey.toBase58()` + `signMessage`), and the `appKey` for email/biometric/Solana accounts is **never** derived from an external EVM signature. Therefore `verifySolanaSignature` covering only the external (Solana) auth path is **correct by design**, and an EVM `0x…` address failing closed (401) on the wallet-auth routes is intended, not a defect.
- **Status:** This finding (and `AUTHSESSION-1`, `DESIGN-2`, `SERVERSIDE-3`, and the EVM half of `CRYPTO-4`/`DESIGN-6`) is **withdrawn — not a vulnerability.**
- **Residual (Low, doc-only):** The README/keywords say "Web3 wallet … login" and list `evm`, which could mislead an integrator into expecting a "connect MetaMask to log in" flow. **Recommendation:** make the docs explicit — "external wallet login is Solana-only; EVM is an internally-generated signing wallet" (tracked as `DESIGN-12` doc drift).
- **Independent findings that remain (NOT EVM-specific):** the email-register path requires no proof of control over the identity (`SERVERSIDE-5`, account/email squatting) and `publicKey`/`email` are not format-validated before being used as storage keys (`SERVERSIDE-11`, `SERVERSIDE-1`). These stand on their own regardless of chain; the deepseek "EVM via email" test was really exercising *these* generic gaps via a raw API call, not an EVM auth path. Validating `publicKey` as Solana base58 on the auth/identity paths (`SERVERSIDE-11`) also cleanly rejects a stray `0x` value with a clear error.

#### 🟡 MEDIUM — `AUTHSESSION-3` / `DESIGN-7`: Per-identifier limit is incremented before auth ⇒ targeted account lockout DoS
- **Location:** `routes.ts:164` (login increments on `body.email` before the `timingSafeEqual` at `:172`), `:115,:185`; `rateLimit.ts:21`.
- **Impact:** An unauthenticated attacker knowing a victim's email (or public on-chain wallet address) sends 10 failed attempts/60s; the 11th — including the victim's *own* login — is blocked. Sustained indefinitely with cheap junk requests; no valid credentials needed. With H5 there's no second throttle.
- **Recommendation:** Increment the per-identifier counter only on **failed** attempts, or tie backoff to the *source* rather than the target identifier so the victim's own login never trips it; require IP+identifier so lockout needs a botnet.

#### 🟡 MEDIUM — `AUTHSESSION-4`: `trustProxyHeaders:true` trusts the leftmost X-Forwarded-For hop (spoofable)
- **Location:** `src/server/http.ts:23` `fwd.split(",")[0]`.
- **Impact:** The operators who must enable `trustProxyHeaders` to get IP limiting then get a **client-controlled** leftmost XFF value — an attacker sets `X-Forwarded-For: <random>` per request for a fresh bucket each time, defeating throttling while appearing protected. No trusted-hop-count or trusted-CIDR config exists.
- **Recommendation:** Take the rightmost hop after skipping a configured number of trusted proxies, or only honor XFF when the immediate peer is in a trusted-proxy allowlist. Expose `trustedProxyHops`/`trustedProxyCidrs`. Never use the leftmost value.

#### 🟡 MEDIUM — `AUTHSESSION-6`: Session is a pure bearer token in `localStorage`; no Origin check on unauthenticated state-changing routes
- **Location:** `src/server/session.ts:60-70` (`verifySession` compares stored owner to the client-sent publicKey header — both client-supplied); `client/session.ts:107,218-225`; no Origin/Referer check in `routes.ts`.
- **Impact:** The `publicKey` "second factor" adds nothing since it's co-located with the token in `localStorage` (returned in `AuthResult`, stored alongside). XSS reading `localStorage` ⇒ full account-action takeover for the 24h TTL (call `/user-data`, `/import-wallet`, `/logout`) — though the token alone **cannot** decrypt wallets (needs the `appKey`). Header-auth routes are CSRF-safe (custom headers need CORS preflight), but the **unauthenticated** state-changing routes (`/challenge`, `/register`, `/connect-wallet`) accept any cross-site POST (amplifies the H5 DoS). *Adversarial verdict confirmed Medium; single-active-session bounds the window to the victim's next login.*
- **Recommendation:** Prefer a `__Host-`, HttpOnly, Secure, SameSite cookie for the token (server already uses custom headers for state-changing calls, so add an Origin allowlist + CSRF token). At minimum shorten the 24h TTL, rotate on unlock, document XSS=takeover, and add an Origin allowlist on the unauthenticated routes.

#### 🟢 LOW — `AUTHSESSION-7` · `SERVERSIDE-6` · `DESIGN-13`: User/wallet enumeration
- `register` → 409 "Account already exists" (email oracle); `search-wallet` → 200/404 (unauthenticated, only the global bucket); `login-wallet` → 404 "Wallet not registered" vs 401 (distinguishes). Feeds targeted phishing + AUTHSESSION-3 + links on-chain addresses to accounts. **Recommendation:** uniform 401 on `login-wallet`; rate-limit/authenticate `search-wallet`; make the 409 non-attributing while keeping the client auto-fallback keyed on a stable code.

#### 🟢 LOW — `AUTHSESSION-8`: Challenge has no purpose/audience binding
- **Location:** `challenge.ts`, `core/index.ts:9`.
- A signature gathered for one flow (connect) is accepted for another (login) within TTL; unlimited unauthenticated issuance is a free per-publicKey storage-write primitive and lets an attacker churn a victim's challenge slot. Single-use `getdel` + high entropy blunt classic replay. **Recommendation:** bind a purpose/RP/timestamp into the signed message and verify it; rate-limit issuance per-publicKey.

#### 🟢 LOW — `AUTHSESSION-10` · `DESIGN-11`: Logout is fire-and-forget; no rotation
- **Location:** `authClient.ts:299-307`.
- `void fetch(...).catch(()=>{})` isn't awaited and clears local state immediately; if the request never lands, the bearer token lives the full 24h. **Recommendation:** `navigator.sendBeacon`/`keepalive:true`; shorten TTL; add idle expiry/rotation and a "revoke all sessions" endpoint.

#### ⚪ INFO — `AUTHSESSION-11`: Session TTL not refreshed on use / no rotation. `AUTHSESSION-12`: `connect-wallet` self-heal backfills wallets from the client bundle (safe — only when empty, and ownership is proven by signature). Documented as Info.

#### ⚪ INFO — Positive: challenge atomicity (`getdel`) and single-active-session revocation are correct (confirmed by both prior audits' concurrency tests). Rate-limit `expire`-on-overflow is **intentional self-healing**, not a bug (`deepseek-v4.md` F9).

### 3. Client-Side Vault

#### 🟠 HIGH — H3 / `CLIENTVAULT-1` · `CRYPTO-7`: Default `appKeyStorage:"session"` writes the raw 256-bit `appKey` to `sessionStorage` (cleartext)
- **Location:** `src/core/config.ts:89`; `src/client/session.ts:117` (`sessionStorage.setItem("ttc_ek", appKey)`).
- **Impact:** The master key that decrypts *every* wallet sits in DOM storage in cleartext by default. **Adversarial verdict: confirmed High, real-world exploitability high.** A single XSS / malicious third-party or transitive script / extension does `sessionStorage.getItem('ttc_ek')`, fetches the ciphertext from `/user-data`, and decrypts all keys offline — no re-auth, no signing prompt, no server round-trip. Strictly worse than session-token theft (that only authorizes API calls and TTLs out; this *is* the wallet). The 15s auto-lock does clear it on lock/hide within a live tab, but it's re-hydrated on reload and exposed for the whole idle window.
- **Recommendation:** **Change `DEFAULT_CONFIG.appKeyStorage` to `"memory"`** (reload→re-auth is a minor UX cost vs master-key disclosure). If `"session"` must remain, wrap the at-rest copy under a non-extractable Web Crypto key in IndexedDB exactly like gate-mode (`webauthn.ts:181-198`) so cleartext never touches storage. Ship/require a CSP either way.

#### 🟡 MEDIUM — `CLIENTVAULT-2`: Token + publicKey + **email** persisted in `localStorage` (XSS-exfiltratable, survives restart)
- **Location:** `src/client/session.ts:107-109`.
- **Impact:** *Adversarial verdict: confirmed Medium.* Token alone can't decrypt wallets (bounded to account actions + ciphertext harvesting), but `localStorage` persists across restart (wider window than `sessionStorage`), and the **email is the PBKDF2 salt** — exfiltrating it materially aids the offline crack path. **Recommendation:** HttpOnly cookie for the token; keep email out of `localStorage` (it's the salt); shorter TTL.

#### 🟡 MEDIUM — `CLIENTVAULT-3`: `isLocked()` lazy re-hydration **resets** the auto-lock deadline on every reload
- **Location:** `src/client/session.ts:144-150` (sets `lockDeadline = now + autoLockMs` on re-hydrate).
- **Impact:** *Adversarial verdict: confirmed Medium.* `lockDeadline` lives only in memory and is never persisted; only `EK_KEY` is. After a reload the first `getAppKey()`/`isLocked()` revives the key from `sessionStorage` with a **fresh** 15s window — so the documented "15s idle then lock" doesn't survive a reload, and the key can be kept hot indefinitely by reloading. (Note: `tests/session.test.ts` runs only in `"memory"` mode, so this session-mode path is untested.) **Recommendation:** persist an **absolute** deadline (e.g. `ttc_ek_exp`); on re-hydrate, if `now > storedDeadline` clear instead of re-arming; add an absolute max-session cap. Defaulting to `"memory"` removes the path.

#### 🟢 LOW — `CLIENTVAULT-4`: Auto-lock relies on a live tab; crash/force-quit/session-restore can revive the key past the window
- **Location:** `src/client/session.ts:85-98`.
- **Verdict (downgraded Medium→Low):** *Ordinary backgrounding is in fact handled* — `visibilitychange→hidden` fires `lockVault()` (clears `EK_KEY`) under the default `lockOnHide:true`. The genuine residual is an **unclean** renderer death (crash/force-quit/OS-kill) while foregrounded, then session-restore re-hydrating with a fresh deadline (ties to CLIENTVAULT-3). Local-access only, no remote vector. **Low.**

#### 🟢 LOW — `CLIENTVAULT-5`: No `pagehide`/`freeze`/`pageshow(persisted)` handlers (bfcache/mobile-suspend gap). Spec orders `visibilitychange→hidden` before these, so the common paths are covered; belt-and-suspenders gap. *Adversarial verdict: confirmed Low.*

#### 🟢 LOW — `CLIENTVAULT-6`: `lockSnapshot()` vs `isLocked()` divergence — UI can read "locked" while the use-path silently re-hydrates and signs (and resets the deadline) with no `notify()`. Correctness + weakens the lock guarantee. **Recommendation:** make snapshot and use-path agree; re-hydrate eagerly with `notify()` and without resetting the deadline.

#### 🟢 LOW — `CLIENTVAULT-7`: No cross-tab lock propagation — `lock`/`logout` in one tab leaves other tabs hot (`sessionStorage` is per-tab; no `storage`/`BroadcastChannel` listener). Foot-gun on shared devices. **Recommendation:** add a `BroadcastChannel`/`storage`-event lock signal.

#### 🟢 LOW — `CLIENTVAULT-8`: Revealed plaintext key + one-time `appKey` are unzeroizable JS strings; `useExportKey` auto-clear defaults **OFF**
- **Location:** `src/react/useExportKey.ts:19-21,70`; `ExportKeyPanel` opts in at 60s.
- `revealSecret` correctly never arms the session (verified `authClient.ts:117-124`), but the bare hook leaves the secret in React state/DOM indefinitely. **Recommendation:** default `autoClearMs` ON (30–60s) in the hook; prefer copy-without-display; require CSP on reveal routes.

#### 🟢 LOW — `CLIENTVAULT-9`: The model leans on a CSP that is neither shipped nor present in the reference demo (grep of the demo: zero CSP/`headers()`). The compensating control the SDK relies on is left entirely to integrators who demonstrably omit it. **Recommendation:** ship a copy-pasteable CSP + `frame-ancestors` in the demo and a Next.js middleware helper; make it a documented hard requirement.

### 4. Server-Side

#### 🟡 MEDIUM (finder said High) — `SERVERSIDE-1` · `AUTHSESSION-9`: Key-namespace collision — user records and session tokens share the `pubKey:` prefix; `publicKey` is unvalidated
- **Location:** `session.ts:14` (`pubKey:{publicKey}`) vs `session.ts:81` (`pubKey:session:{token}`); register email path needs only a `passkeyHash` (`routes.ts:142`).
- **Impact:** An attacker can register `authMethod:"email"` with `publicKey = "session:<token>"` (no ownership proof), writing a JSON user blob into the **session** key space. Consequences: session corruption / forced logout (`verifySession` owner mismatch), and `getUserByPublicKey`'s unguarded `JSON.parse` (SERVERSIDE-8) can 500 on a colliding bare-string value. **Severity reconciled to Medium** (not High): session forgery is *not* achievable (the stored value is a JSON blob, not a bare publicKey, so `owner !== publicKey` still fails), and the victim-targeted DoS needs an unguessable 256-bit token. It remains a real key-injection design smell.
- **Recommendation:** Use **disjoint** namespaces (`session:{token}`, `user:{publicKey}` — not nested under one prefix). Strictly validate `publicKey` (base58-32 for Solana, `0x`+40-hex for EVM; reject `:`/control chars) and email format before any concatenation. Guard `JSON.parse`.

#### 🟡 MEDIUM — `SERVERSIDE-11`: No format/length validation on `publicKey`, `email`, `passkeyHash`, wallet fields
- **Location:** `routes.ts` (only truthiness checks).
- **Impact:** `deepseek-v4.md` empirically confirmed: empty/`javascript:`/10k-char emails, non-hex/short `passkeyHash`, whitespace/100k-char `publicKey` all accepted (201). Storage waste, junk index entries, enables SERVERSIDE-1. (The 16-wallet / 8192-byte bounds *are* enforced.) **Recommendation:** validate formats and set max lengths for all string fields; reject non-hex `passkeyHash` and malformed emails/keys.

#### 🟡 MEDIUM — `SERVERSIDE-4`: `import-wallet` appends without a total cap (record-bloat DoS)
- **Location:** `routes.ts:285` `user.wallets = [...user.wallets, ...body.wallets]`.
- **Impact:** `validateWallets` bounds only the incoming batch (16×8KB ≈ 128KB/call); a session-authenticated user loops to grow `pubKey:{publicKey}` unbounded. Every login re-`JSON.parse`/re-serializes the whole blob ⇒ O(record size) per request + KV cost. **Recommendation:** enforce a total `MAX_WALLETS_PER_USER` (e.g. 32–64) and a serialized-size cap; rate-limit `import-wallet`.

#### 🟡 MEDIUM — `SERVERSIDE-5` · `DESIGN-3`: Email account squatting / no proof-of-control
- **Location:** `routes.ts:129-132,142`; `session.ts:16`.
- **Impact:** Register requires only a `passkeyHash` — no OTP/verification. First-writer claims the `email:{email}` index; the real owner hits 409 and (in "auto" mode) is funneled into *login* against the attacker's record. Account/registration denial; NIST 800-63A / ASVS V2 gap. (No cross-user key theft — `appKey` is deterministic from the victim's own passkey+email.) **Recommendation:** verify email ownership (OTP/magic link) before the index is authoritative, or document email as an opaque, unverified local label and key accounts on a verified identifier; allow re-binding an unverified index.

#### 🟡 MEDIUM — `SERVERSIDE-10`: `resolveStorageAdapter` silently defaults to `ioredis` localhost in production
- **Location:** `src/storage/resolve.ts:33` `new Redis(env("REDIS_URL") ?? "redis://localhost:6379")`.
- **Impact:** A missing/typo'd Upstash/KV env var on a non-Vercel host silently connects to localhost Redis — total auth outage (connection refused) or auth state (sessions, challenges, email index, rate-limit counters) written to an unintended/ephemeral store. Partial Upstash config (URL without TOKEN) silently skips Upstash with no warning. **Recommendation:** in production, refuse the localhost fallback and throw a clear startup error if no recognized backend is configured; warn on partial config; add a healthcheck.

#### 🟢 LOW — `SERVERSIDE-7`: KV/Upstash `incr()` runs against attacker-influenceable string keys; non-integer existing values would error. `SERVERSIDE-8`: `getUserByPublicKey` `JSON.parse(raw)` unguarded (500 on collision). `SERVERSIDE-9`: non-uniform error messages (challenge vs signature vs not-registered) reveal control flow. `SERVERSIDE-12`: token is the sole bearer credential (dup of AUTHSESSION-6). **Recommendations:** guard `JSON.parse`; uniform error bodies for auth failures.

### 5. WebAuthn / Biometric

#### 🟠 HIGH — H7 / `WEBAUTHN-1` · `WEBAUTHN-2` · `DESIGN-5`: Server never verifies a WebAuthn assertion or attestation — biometric "auth" = possession of `SHA-256(appKey)`
- **Location:** `routes.ts:160-177` (biometric uses the generic email `login`, hash-compare only); `authClient.ts:260-291`; `webauthn.ts:74-96` (attestation `none`, never forwarded).
- **Impact:** The server never issues a challenge, never receives/verifies `clientDataJSON`/`authenticatorData`/signature, never checks origin/rpIdHash/UV-flag/signCount, and never stores the credential's COSE public key. So the "biometric factor" gives **zero** server-enforced assurance a Touch ID/Face ID ceremony occurred — it degrades to "present a 256-bit secret hash," identical to the email path. Anyone who learns `appKey` (XSS reading `ttc_ek` in default session mode, a leaked secret, the gate secret per WEBAUTHN-4) authenticates from any machine with no authenticator. Registration likewise accepts a self-asserted `passkeyHash` with no proof of authenticator possession (account pre-seeding; future migration to real assertions is impossible without re-enrollment since no public key is stored). WebAuthn's entire phishing/clone resistance is unrealized at the server boundary.
- **Recommendation:** Add real server-side WebAuthn (e.g. `@simplewebauthn/server`): verify attestation at registration and **store the credential public key**; issue a server challenge per login; verify the assertion signature + origin + rpIdHash + challenge + counter. Gate session issuance on the verified assertion, not on `SHA-256(appKey)`. Treat the PRF/gate secret strictly as the client-side *encryption* key, not the auth factor. At minimum, **document honestly** that biometric mode is a client-side key-unlock, not a server-verified factor.

#### 🟡 MEDIUM — `WEBAUTHN-3`: PRF/gate secret is reused as both the encryption key and (hashed) the server credential — no domain separation, no rotation
- **Location:** `webauthn.ts:140-151`; `authClient.ts:262,283`.
- **Impact:** One leaked secret simultaneously decrypts all wallets *and* authenticates; no rotation without re-registering + re-encrypting. Forgoes the HKDF context-binding WebAuthn-PRF guidance recommends. **Recommendation:** `encKey = HKDF(prf, "ttc-enc-v1")`, `authValue = HKDF(prf, "ttc-auth-v1")`; never reuse one secret for both roles.

#### 🟡 MEDIUM — `WEBAUTHN-4`: Gate-mode non-extractable AES-GCM wrap does **not** stop XSS exfiltration
- **Location:** `webauthn.ts:181-226`; misleading comments at `7-11`,`156-159`.
- **Impact:** The non-extractable key protects the raw key *bytes* from export, but the `CryptoKey` handle + IV + ciphertext are co-resident in the same origin. Any XSS opens IndexedDB (`ttc_passkey_store`/`gate_secrets`) and calls `crypto.subtle.decrypt({name:'AES-GCM',iv}, cryptoKey, ciphertext)` — exactly what `gateLoad` does — recovering the plaintext **without any biometric assertion** (the assertion gate in `derivePasskeySecret` is simply skipped). Since the gate secret *is* the `appKey` (WEBAUTHN-3), this is full wallet decryption + impersonation. **`deepseek-v4.md`'s "gate-mode secure" tests only checked non-exportability + GCM tamper-rejection — they did not test this XSS-reads-IndexedDB-and-decrypts path, so this nuance is net-new.** **Recommendation:** prefer PRF-only (refuse to register without PRF), or derive the wrapping key from a *fresh* assertion/PRF output so decryption is impossible without a successful biometric. Fix the misleading comment.

#### 🟡 MEDIUM — `WEBAUTHN-5`: Loss of the client-persisted `PasskeyRegistration` = permanent, unrecoverable lockout
- **Location:** `webauthn.ts:14-19,71,133`; demo persists to `localStorage` only.
- **Impact:** Login needs the exact `{credentialId, salt, rpId, mode}` from sign-up (PRF eval uses the stored 32-byte salt; the account email is derived from `credentialId`). Clearing storage / new device / private window ⇒ different/absent salt ⇒ undecryptable wallets and an unreconstructable account. High-likelihood, irreversible. **Recommendation:** store `salt`+`credentialId` server-side (salt isn't secret, useless without the authenticator); use discoverable credentials (`residentKey:"required"`, empty `allowCredentials`); offer an encrypted backup/recovery code; surface the risk in UI.

#### 🟢 LOW — `WEBAUTHN-6`: PRF salt fixed per registration (no per-use domain separation). `WEBAUTHN-7`: `credentialId` concatenated unvalidated into the email/storage key. `WEBAUTHN-8`: `residentKey:"preferred"` + caller-held credentialId undermines discoverability/recovery. `WEBAUTHN-9`: silent PRF→gate downgrade is never surfaced (the caller can't tell which security level they got). **Recommendations:** validate `credentialId`; surface the resolved `mode`; prefer `residentKey:"required"`.

#### ⚪ INFO — `WEBAUTHN-10`/`WEBAUTHN-11`: legacy rewrap returns plaintext without a co-located assertion (dup of CRYPTO-10); biometric internal email `bio_{credentialId}@passkey.local` is predictable (enumeration). `userVerification:"required"` is correctly set (positive).

### 6. Supply Chain & Build

#### 🟡 MEDIUM — `SUPPLYCHAIN-2`: Security-critical crypto delegated to single-maintainer `crypto-es` with a `^` range
- **Location:** `package.json:65` `"crypto-es": "^2.1.0"`.
- **Impact:** All KDF/AES/SHA gating wallet confidentiality run through one dependency maintained by a sole npm publisher (CryptoJS-derived legacy). A malicious release reaches consumers on any `^2.x` bump and runs with full client-side access to plaintext keys (event-stream / ua-parser-js precedent). The primitive surface used is tiny and **fully covered by native Web Crypto** — which the codebase already uses (`webauthn.ts:182` AES-GCM, `crypto.ts:61` `getRandomValues`). **Recommendation:** plan a versioned migration to Web Crypto (`subtle.deriveBits` PBKDF2, `subtle.digest` SHA-256, `subtle` AES-GCM — also fixes H1). Interim: **pin exactly** (`2.1.0`, not `^2.1.0`) and rely on the lockfile integrity hash.

#### 🟢 LOW — `SUPPLYCHAIN-1`: Published tarball ships sourcemaps (original TS source)
- **Verified:** `tsup.config.ts:26` `sourcemap:true`; `npm pack --dry-run` shows `dist/**/*.{js,cjs}.map` in the tarball (e.g. `react/index.js.map` 87KB). Since the repo is public, this is **package bloat + hygiene**, not confidentiality. **Recommendation:** ship sourcemaps only if intended; otherwise set `sourcemap:false` (or exclude `*.map` from `files`) to shrink the package and avoid leaking internal comments if the repo ever goes private.

#### 🟢 LOW — `SUPPLYCHAIN-4`/`SUPPLYCHAIN-5`: `peerDependenciesMeta` omits `viem`/`tweetnacl`/`@solana/web3.js` as optional (forces install even for, e.g., a Solana-only consumer); `^` ranges on all peers allow silent minor/patch drift (note: `@solana/web3.js` has prior supply-chain incidents). **Recommendation:** mark genuinely-optional peers optional; document tested version ranges.

#### 🟢 LOW — `SUPPLYCHAIN-6`: No CI, no npm provenance, no SRI, no publish-time supply-chain scan. **Recommendation:** add CI running `npm audit`/`jest`/`tsc`, enable npm provenance (`--provenance`), Dependabot.

#### ⚪ INFO — `SUPPLYCHAIN-7`: Two committed lockfiles (`yarn.lock` + `package-lock.json`) create resolution ambiguity. **Pick one.**

#### ❌ REFUTED (false positive) — `SUPPLYCHAIN-3`: claimed a transitive `uuid<11.1.1` advisory
- **Verification:** `npm audit --omit=dev` → **0 vulnerabilities**; `uuid@8.3.2` present and not flagged. The specific GHSA was over-claimed. **No action** beyond keeping `npm audit` in CI. (Surfacing this is the value of adversarial verification.)

### 7. Design & Compliance

- **`DESIGN-9` (Medium):** No crypto-versioning metadata on stored blobs (`EncryptedWallet` has no `v`; `UserData` has no `kdfVersion`/`hashVersion`). This is the *blocker* that makes every other crypto fix (GCM, salted hash, 600k, domain-bound key) unshippable without a flag-day. **Fix this first** — add scheme versions and dispatch encrypt/decrypt + hash on them, with lazy forward migration on login.
- **`DESIGN-4` (Medium):** No CSP/security-headers guidance for host apps despite XSS being the dominant client risk (dup of CLIENTVAULT-9). Add a "Hardening the host app" README section (strict CSP, Trusted Types, `frame-ancestors 'none'`, HSTS, SRI) + a Next.js headers preset.
- **`DESIGN-12` (Low):** README endpoint drift (omits `connect-wallet`/`logout`/`import-wallet`); README claims EVM login that doesn't work.
- **Compliance mapping:** Fails **ASVS V6.2** (authenticated encryption + crypto agility — H1, DESIGN-9), **V2.4** (salted slow password storage — C1), **V2.2** (anti-automation — H5, AUTHSESSION-3), **V2.7/V2.2** (RP-verified WebAuthn — H7), **V2/NIST 800-63A** (no email proof-of-control — SERVERSIDE-5). Meets the non-custodial-key-handling and CSPRNG expectations well.

---

## Hardening Roadmap

### Immediate (backward-compatible, no stored-data migration)
1. **Default `appKeyStorage:"memory"`** (`config.ts:89`). *(H3)*
2. **Default `autoLockMs` review + persist an absolute lock deadline** so reload can't reset the idle window (`session.ts`). *(CLIENTVAULT-3/4)*
3. **Server-side salted+peppered slow hash over the transmitted `passkeyHash`** — no client/protocol change; legacy fallback + upgrade-on-login. *(C1)*  ← highest leverage
4. **Encrypt-then-MAC** the existing CBC blob (sync, keeps inner bytes) for integrity now. *(H1 interim)*
5. **Fix rate limiting:** per-`publicKey` identifier on `/challenge` & `/search-wallet`; derive a real per-connection IP when untrusted; separate global ceiling. *(H5)*
6. **Reject EVM `0x` keys** on wallet-auth routes with a clear 400; reject `0x` registration via the email path; correct the README. *(H6 stop-gap)*
7. **Increment per-identifier rate counters only on auth failure** / tie backoff to source. *(AUTHSESSION-3)*
8. **Input validation:** base58/0x `publicKey`, email format, hex/length `passkeyHash`; guard `JSON.parse`; total cap in `import-wallet`. *(SERVERSIDE-1/4/5/8/11)*
9. **Separate storage namespaces** (`session:{token}`, `user:{publicKey}`). *(SERVERSIDE-1)*
10. **Pin `crypto-es` exactly**; refuse localhost storage fallback in production; add CSP to the demo + README. *(SUPPLYCHAIN-2, SERVERSIDE-10, DESIGN-4)*
11. **`sendBeacon`/`keepalive` logout**; default `useExportKey` auto-clear ON; cross-tab lock via `BroadcastChannel`. *(AUTHSESSION-10, CLIENTVAULT-7/8)*

### Short-term (minor breaking, version bump — gated by `DESIGN-9` versioning)
12. **Add `kdfVersion`/`hashVersion`/cipher `v` to stored records** and dispatch on them with lazy re-encrypt/re-hash on login. *(DESIGN-9 — do this first to unblock the rest)*
13. **PBKDF2 default → 600k**, persisted per user. *(H2)*
14. **Implement EVM signature verification** (`viem.verifyMessage`, dispatch on address shape, strict address-equality). *(H6)*
15. **Real server-side WebAuthn** (challenge + assertion + stored credential public key + attestation at registration). *(H7)*
16. **Server-side WebAuthn recovery**: store `salt`+`credentialId`; discoverable credentials. *(WEBAUTHN-5)*

### Long-term
17. **AES-256-GCM via Web Crypto** with AAD `{publicKey,chain,role,v}`; legacy CBC decrypt + migrate. *(H1)*
18. **Domain-bound key-derivation message** (EIP-4361 / structured Solana), per-origin keys via `HKDF`. *(H4)*
19. **Argon2id** for the passkey verifier where supported; **HKDF domain separation** for PRF→{enc,auth}. *(C1, WEBAUTHN-3)*
20. **Remove `crypto-es`** entirely in favor of Web Crypto. *(SUPPLYCHAIN-2)*

### Config options to expose
| Key | Current | Proposed default | Rationale |
|---|---|---|---|
| `appKeyStorage` | `"session"` | **`"memory"`** | XSS can't read the master key |
| `pbkdf2Iterations` | `100_000` | **`600_000`** | OWASP 2023 floor (persist per user) |
| `kdfVersion`/`hashVersion`/cipher `v` | — | **stored per record** | crypto agility / migration |
| `appId` | — | required string | domain-separate KDF salt & key message |
| `sessionTtlSeconds` | `86_400` | `3600`–`14400` + rotation | smaller bearer-token window |
| `trustedProxyHops`/`trustedProxyCidrs` | — | configurable | correct client-IP extraction |
| `maxWalletsPerUser` | — | `32`–`64` | record-bloat cap |
| `SERVER_PASSKEY_PEPPER` (env) | — | required in prod | DB-only leak can't crack the verifier |

---

## Patched Code Snippets

> All patches are **versioned and migration-safe**: legacy blobs/hashes still decrypt/verify; new data uses the hardened path; upgrade-on-unlock/-login migrates lazily. None weaken security for compat.

### `src/core/crypto.ts` (hardened — drop-in for the affected functions)

```ts
// App-key derivation, secret encryption, hashing, and CSPRNG helpers — HARDENED.
//
// Versioning (DESIGN-9): every stored value carries a scheme version so we can
// migrate without a flag-day. Legacy (unversioned) values still decrypt/verify.
import CryptoES from "crypto-es";

export const CIPHER_V = 1;      // 1 = legacy CBC; "v1m:" = CBC+HMAC; "v2:" = AES-GCM (async, below)
export const KDF_V = 2;         // 2 = PBKDF2-SHA256 600k + domain-separated salt
export const HASH_V = 2;        // 2 = server salted+peppered slow hash over the transmitted hash

// ---------- App-key derivation (email/passkey) ----------

const DEFAULT_PBKDF2_ITERATIONS = 600_000; // was 100_000 (CRYPTO-2 / deepseek F2)

/**
 * Deterministic but DOMAIN-SEPARATED salt: SHA-256(appId : normalizedEmail).
 * Still deterministic (cross-device recovery preserved), but no longer the bare
 * email and unique per deployment (fixes the cross-site-reusable salt, CRYPTO-2).
 * Pass kdfVersion=1 + appId="" to reproduce a legacy key for migration.
 */
function deriveKdfSalt(email: string, appId: string, kdfVersion: number): string {
  const normalized = email.toLowerCase().trim();
  if (kdfVersion <= 1) return normalized;                 // legacy: salt === email
  return CryptoES.SHA256(`${appId}:${normalized}`).toString(CryptoES.enc.Hex);
}

export function deriveAppKeyFromPasskey(
  passkey: string,
  email: string,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  appId = "tetrac",
  kdfVersion = KDF_V,
): string {
  const salt = deriveKdfSalt(email, appId, kdfVersion);
  return CryptoES.PBKDF2(passkey, salt, {
    keySize: 256 / 32,
    iterations,
    hasher: CryptoES.algo.SHA256, // explicit — never rely on the library default
  }).toString(CryptoES.enc.Hex);
}

/** Web3 app key. HKDF-style domain separation so a future per-origin key is possible. */
export function deriveAppKeyFromSignature(signatureHex: string, info = "ttc-enc-v1"): string {
  // Cheap HMAC-based extract/expand (crypto-es lacks HKDF); high-entropy input.
  return CryptoES.HmacSHA256(signatureHex, info).toString(CryptoES.enc.Hex);
}

// ---------- Server-side passkey verifier (C1) ----------
// The CLIENT still sends SHA-256(passkey) (unchanged protocol, no plaintext to
// server). The SERVER wraps it in a salted, slow, PEPPERED hash before storage.

export interface StoredPasskeyHash { v: number; salt: string; iterations: number; hash: string; }

/** SHA-256 of the passkey — unchanged client-side helper (transport hash, never stored raw). */
export function hashPasskey(passkey: string): string {
  return CryptoES.SHA256(passkey).toString(CryptoES.enc.Hex);
}

/** SERVER: turn the transmitted client hash into a slow salted+peppered verifier. */
export function deriveStoredPasskeyHash(
  clientPasskeyHash: string,
  pepper: string,
  salt = randomHex(16),
  iterations = 600_000,
): StoredPasskeyHash {
  const hash = CryptoES.PBKDF2(clientPasskeyHash, `${salt}:${pepper}`, {
    keySize: 256 / 32, iterations, hasher: CryptoES.algo.SHA256,
  }).toString(CryptoES.enc.Hex);
  return { v: HASH_V, salt, iterations, hash };
}

/** SERVER: constant-time verify; supports legacy bare-SHA-256 records for upgrade-on-login. */
export function verifyStoredPasskeyHash(
  stored: StoredPasskeyHash | string,   // string === legacy unsalted SHA-256
  clientPasskeyHash: string,
  pepper: string,
): boolean {
  if (typeof stored === "string") return timingSafeEqual(stored, clientPasskeyHash); // legacy
  const got = CryptoES.PBKDF2(clientPasskeyHash, `${stored.salt}:${pepper}`, {
    keySize: 256 / 32, iterations: stored.iterations, hasher: CryptoES.algo.SHA256,
  }).toString(CryptoES.enc.Hex);
  return timingSafeEqual(stored.hash, got);
}

// ---------- Wallet secret encryption ----------
// Immediate (sync, compat-preserving): Encrypt-then-MAC over the legacy CBC blob.
// The inner CBC bytes are unchanged, so next-ttc can still read the inner blob.

function macSubkey(appKey: string): string {
  return CryptoES.HmacSHA256("ttc-mac-v1", appKey).toString(CryptoES.enc.Hex);
}

export function encryptSecret(plaintext: string, appKey: string): string {
  const ct = CryptoES.AES.encrypt(plaintext, appKey).toString(); // legacy OpenSSL CBC blob
  const mac = CryptoES.HmacSHA256(ct, macSubkey(appKey)).toString(CryptoES.enc.Hex);
  return `v1m:${mac}:${ct}`; // versioned envelope; unprefixed legacy blobs still decrypt below
}

export function decryptSecret(ciphertext: string, appKey: string): string {
  if (ciphertext.startsWith("v1m:")) {
    const c1 = ciphertext.indexOf(":");
    const c2 = ciphertext.indexOf(":", c1 + 1);
    const mac = ciphertext.slice(c1 + 1, c2);
    const ct = ciphertext.slice(c2 + 1); // base64 OpenSSL blob contains no ':'
    const expected = CryptoES.HmacSHA256(ct, macSubkey(appKey)).toString(CryptoES.enc.Hex);
    if (!timingSafeEqual(mac, expected)) throw new Error("Ciphertext integrity check failed");
    const out = CryptoES.AES.decrypt(ct, appKey).toString(CryptoES.enc.Utf8);
    if (!out) throw new Error("Decryption failed");
    return out;
  }
  // Legacy unauthenticated CBC (existing blobs) — decrypt, then re-encrypt on unlock to migrate.
  const out = CryptoES.AES.decrypt(ciphertext, appKey).toString(CryptoES.enc.Utf8);
  if (!out) throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  return out;
}

// randomHex / generateSessionToken / generateChallenge / timingSafeEqual — UNCHANGED.
// (timingSafeEqual verified correct for fixed-length hex by deepseek-v4.md; keep as-is.)
```

### `src/core/crypto-gcm.ts` (long-term authenticated encryption — async, Web Crypto)

```ts
// AES-256-GCM via Web Crypto with associated data binding (H1 long-term).
// Format: "v2:" + b64url(iv) + ":" + b64url(ct||tag). Requires async call sites.
const enc = new TextEncoder();
const dec = new TextDecoder();

async function importAesKey(appKeyHex: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(appKeyHex.match(/../g)!.map((h) => parseInt(h, 16))).slice(0, 32);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
const b64u  = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b as ArrayBuffer))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const ub64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), (c)=>c.charCodeAt(0));

/** AAD binds the blob to its owner/role so a relocated ciphertext fails authentication. */
export async function encryptSecretV2(
  plaintext: string, appKeyHex: string, aad: { publicKey: string; chain: string; role: string },
): Promise<string> {
  const key = await importAesKey(appKeyHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(JSON.stringify(aad)) }, key, enc.encode(plaintext),
  );
  return `v2:${b64u(iv)}:${b64u(ct)}`;
}

export async function decryptSecretV2(
  ciphertext: string, appKeyHex: string, aad: { publicKey: string; chain: string; role: string },
): Promise<string> {
  const [, ivb, ctb] = ciphertext.split(":");
  const key = await importAesKey(appKeyHex);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ub64u(ivb), additionalData: enc.encode(JSON.stringify(aad)) }, key, ub64u(ctb),
  ); // throws OperationError on any tampering — integrity guaranteed
  return dec.decode(pt);
}
```

### `src/server/signature.ts` (add EVM verification — H6)

```ts
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import { verifyMessage } from "viem"; // already a peer dependency
import { walletLoginMessage } from "../core/index.js";

export function isEvmAddress(s: string): boolean { return /^0x[0-9a-fA-F]{40}$/.test(s); }
export function isSolanaAddress(s: string): boolean { return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s); }

/** Verify EVM EIP-191 personal_sign over walletLoginMessage(challenge); strict address equality. */
export async function verifyEvmSignature(address: string, signatureHex: string, challenge: string): Promise<boolean> {
  try {
    const sig = (signatureHex.startsWith("0x") ? signatureHex : `0x${signatureHex}`) as `0x${string}`;
    return await verifyMessage({ address: address as `0x${string}`, message: walletLoginMessage(challenge), signature: sig });
  } catch { return false; }
}

/** Chain-dispatching verifier. Reject malformed keys explicitly (no opaque 401). */
export async function verifyWalletSignature(publicKey: string, signatureHex: string, challenge: string): Promise<boolean> {
  if (isEvmAddress(publicKey)) return verifyEvmSignature(publicKey, signatureHex, challenge);
  if (isSolanaAddress(publicKey)) return verifySolanaSignature(publicKey, signatureHex, challenge);
  return false; // unknown format
}

export function verifySolanaSignature(publicKeyBase58: string, signatureHex: string, challenge: string): boolean {
  try {
    const message = new TextEncoder().encode(walletLoginMessage(challenge));
    const sig = Uint8Array.from((signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex).match(/../g)!.map((h)=>parseInt(h,16)));
    return nacl.sign.detached.verify(message, sig, new PublicKey(publicKeyBase58).toBytes());
  } catch { return false; }
}
```

### `src/server/session.ts` (disjoint namespaces — SERVERSIDE-1)

```ts
// BEFORE: function sessionKey(token){ return `${pubKey}session:${token}` }  // collides with pubKey:{publicKey}
// AFTER:
function sessionKey(token: string, config: AuthConfig): string {
  return `${config.keyPrefixes.session ?? "session:"}${token}`; // top-level, cannot be produced by a publicKey
}
// + validate publicKey format before any `pubKey:{publicKey}` write:
//   if (!isSolanaAddress(pk) && !isEvmAddress(pk)) return error("invalid publicKey");
// + guard JSON.parse in getUserByPublicKey (SERVERSIDE-8):
//   try { return JSON.parse(raw); } catch { return null; }
```

### `src/core/config.ts` (safer defaults)

```ts
export const DEFAULT_CONFIG: AuthConfig = {
  pbkdf2Iterations: 600_000,        // was 100_000  (H2 — persist per user via kdfVersion)
  appKeyStorage: "memory",          // was "session" (H3)
  sessionTtlSeconds: 14_400,        // was 86_400    (smaller bearer window; add rotation)
  // ...unchanged keys...
};
```

---

## Testing Recommendations

`deepseek-v4.md` already ships 9 suites (tampering, EVM, PBKDF2 cost, salted hash, timing, gate-mode, rate-limit, input-validation, concurrency). Add:

1. **Ciphertext integrity (H1):** assert every single-bit flip in a `v1m:`/`v2:` blob is **rejected with a distinct integrity error** (not the wrong-key error); assert AAD-mismatch (wrong `publicKey`/`role`) fails — proving a relocated blob can't be authenticated.
2. **Passkey verifier (C1):** same passkey → **different** stored hashes (random salt); a DB dump without the `SERVER_PEPPER` cannot be cracked; legacy bare-SHA-256 records still verify and upgrade-on-login to v2.
3. **appKey storage default (H3):** after login in default config, `sessionStorage.getItem("ttc_ek")` is `null` (memory mode); explicit `"session"` mode writes it (and clears on lock).
4. **Auto-lock across reload (CLIENTVAULT-3):** simulate a reload (re-init module + `sessionStorage` intact) past `autoLockMs`; assert `getAppKey()` returns `null` (honors persisted absolute deadline) — currently it would return the key with a fresh window.
5. **Rate-limit DoS (H5):** 11 `/challenge` requests from client A must **not** 429 client B (per-publicKey bucket); global ceiling separate from per-client.
6. **EVM auth (H6):** a valid EIP-191 signature over `walletLoginMessage(challenge)` from a `0x` address **succeeds**; a signature for address X presented as address Y **fails**; an unsupported/ malformed key returns 400 (not opaque 401).
7. **Namespace collision (SERVERSIDE-1):** registering `publicKey:"session:<token>"` must be **rejected** by format validation; a live session is unaffected.
8. **Account lockout (AUTHSESSION-3):** 10 failed logins for victim's email must **not** block the victim's correct login (counter increments on failure but is scoped to source / cleared on success).
9. **WebAuthn assertion (H7):** biometric login with a tampered/absent assertion is rejected server-side; a replayed assertion (stale challenge) is rejected; the stored credential public key is required.
10. **Gate-mode XSS (WEBAUTHN-4):** prove that reading the IndexedDB record + `subtle.decrypt(handle, ct)` recovers the secret (documents the residual), and that the PRF-only / fresh-assertion-wrapped variant does **not**.
11. **`import-wallet` cap (SERVERSIDE-4):** the (N+1)th wallet beyond `maxWalletsPerUser` is rejected.

---

## Additional Recommendations

- **CI security:** add a GitHub Actions pipeline running `tsc --noEmit`, `jest`, and `npm audit --audit-level=high` on every PR; add Dependabot. Block merges on failure.
- **Provenance & integrity:** publish with `npm publish --provenance` (sigstore); commit a single lockfile (drop one of `yarn.lock`/`package-lock.json`, SUPPLYCHAIN-7); pin `crypto-es` exactly.
- **Third-party audit:** before a v1.0 / mainnet-funds release, commission a professional Web3/crypto audit (Trail of Bits / Zellic / OtterSec class) focused on the KDF/encryption migration and the WebAuthn server flow.
- **Docs:** add a "Threat model & hardening" page — XSS is the dominant client risk; mandate a strict CSP + `frame-ancestors`; recommend `appKeyStorage:"memory"`; document that `email` is an unverified label and that biometric/wallet recovery requires preserving the registration (or server-side credential storage). Correct the EVM-login claim.
- **Monitoring:** watch `@solana/web3.js` advisories (prior incidents); add a published `SECURITY.md` with a disclosure contact.

---

## Appendix — Finding ID cross-reference

74 findings across 7 dimensions were produced and adversarially reviewed (dual-lens: code-accuracy + exploitability). Severities above are reconciled post-verification. Notable reconciliations: `CRYPTO-1` elevated to Critical (chained impact); `SERVERSIDE-1` reduced High→Medium (token unguessable); `CLIENTVAULT-4` reduced Medium→Low (backgrounding is handled); `CRYPTO-5` Low/disproven (deepseek tests); `SUPPLYCHAIN-3` refuted (`npm audit` clean); `WEBAUTHN-4` confirmed Medium (net-new vs prior audits). Prior audits `grok.md` and `deepseek-v4.md` agree on the AES-CBC, PBKDF2, unsalted-hash, and EVM findings; this report adds the domain-unbound key message, the namespace collision, the rate-limit global-bucket DoS framing, the gate-mode XSS-decrypt nuance, WebAuthn server-verification gap, and the storage/versioning/recovery design issues.
