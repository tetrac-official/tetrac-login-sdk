# Security Audit — `@tetrac/login-sdk` v0.6.0

| | |
|---|---|
| **Target** | `@tetrac/login-sdk` v0.6.0 (`/Users/mac/Documents/TTC/tetrac-login-sdk`) |
| **Commit / branch** | `ae91299` on `v0.5.1` |
| **Scope** | All of `src/` (8,523 LOC, 62 files), `package.json`, build config, CI workflows, generated SQL schemas |
| **Date** | 2026-08-05 |
| **Method** | 13-dimension parallel agent audit + partial adversarial verification + first-hand review of every security-critical file |
| **Out of scope** | `node_modules/`, `dist/` (reviewed only for packaging), the integrating application's own security posture |

---

## 0. Verification status — read this first

This audit was produced by a 13-dimension automated fan-out followed by a two-lens adversarial verification pass. **The verification pass did not complete**: 207 of 240 agents aborted on an API session limit. All 13 discovery agents and the threat-model agent finished (112 raw findings); only 19 adversarial verdicts landed, and the completeness critic and remediation-plan agents never ran.

Consequently **every finding below carries an explicit provenance tag**, and no finding is presented as machine-confirmed unless it actually is:

| Tag | Meaning |
|---|---|
| **`[first-hand]`** | I read the cited code and its callers myself during this audit and confirmed the behaviour. |
| **`[adversarial]`** | Survived two independent skeptic agents instructed to refute it. |
| **`[candidate]`** | Reported by a discovery agent with quoted evidence, but **not** independently verified. Treat as a lead, not a conclusion. |

Findings ranked **Critical** and **High** are all `[first-hand]`, `[adversarial]`, or both. The `[candidate]` items are listed honestly in §6 rather than silently dropped or silently promoted.

**Do not read the raw workflow summary** (`confirmed: 5, refuted: 107`) as a result. Findings whose verifier agents *errored* were tallied as "refuted" by the aggregation logic. That number is an artifact of the outage, not a judgement about the code.

---

## 1. Executive summary

`@tetrac/login-sdk` is a non-custodial authentication SDK. Wallet private keys are generated in the browser, encrypted under a key derived from a user secret, and only the ciphertext reaches the server. The security engineering here is, in most places, **well above average**: parameterised SQL throughout, expiry enforced on the read path, atomic challenge consumption, session tokens persisted only as SHA-256 digests, an in-memory-only app key with aggressive auto-lock, and code comments that document prior audit findings and the reasoning behind each control. Several classes of bug that this design invites have already been found and fixed (see §5).

The problems that remain cluster into four themes:

1. **The Web3 login message is not domain-bound.** This is the one finding that breaks the product's core promise. A phishing site can harvest both signatures the SDK asks for and use them to log in as the victim *and* decrypt the victim's wallets. (C-1)
2. **The WebAuthn "gate" fallback is a UI gate, not a cryptographic one.** Its secret is recoverable by any same-origin script with no biometric ceremony, and accounts fall back into this mode silently. (H-1, H-2)
3. **The secret that encrypts every wallet has no strength floor.** A user may type `hunter2`; a database read then permits an offline attack whose only cost is PBKDF2. (H-3)
4. **Unauthenticated endpoints permit targeted denial of service and unbounded storage growth**, because rate-limit buckets are keyed on attacker-chosen identifiers and the IP bucket is disabled by default. (H-4 … H-7)

### Severity counts

| Severity | Count | IDs |
|---|---|---|
| Critical | 1 | C-1 |
| High | 7 | H-1 … H-7 |
| Medium | 14 | M-1 … M-14 |
| Low / Informational | — | §6 (candidate list, unverified) |

### The single most important sentence in this report

> The SDK's non-custodial guarantee currently rests on the user never signing the app-key message on a site they do not control — and the SDK gives them nothing in the signing prompt with which to tell the difference.

---

## 2. Threat model

### 2.1 Architecture

Three layers, no server of its own — the integrator mounts the handlers in their own app and points them at their own database.

| Layer | Entry point | Role |
|---|---|---|
| Core | [src/core/index.ts](src/core/index.ts) | Pure: types, config, crypto, Solana off-chain encoders |
| Client | [src/client/authClient.ts](src/client/authClient.ts) | Derives app key, generates + encrypts wallets, holds the vault |
| Server | [src/server/routes.ts:102](src/server/routes.ts#L102) | 9 handlers over the Web `Request`/`Response` API |
| Storage | [src/storage/store.ts:92](src/storage/store.ts#L92) | `AuthStore` port; KV backends bridged by `KvAuthStore` |

**HTTP surface** ([src/next/routes.ts:25-38](src/next/routes.ts#L25-L38)) — POST `challenge`, `register`, `login`, `login-wallet`, `connect-wallet`, `import-wallet`, `logout`; GET `user-data`, `search-wallet`.

**Keyspace.** Every per-user key is app-scoped via `appScoped(prefix, appId, id)` → `` `${prefix}${appId}:${id}` `` ([src/server/keys.ts:12](src/server/keys.ts#L12)), with disjoint prefixes. `appId` is validated against `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — which excludes `:` — *before* it reaches a key ([src/server/routes.ts:56](src/server/routes.ts#L56)). The email index is the deliberate exception: bare `email:{address}` with `appId` as a hash field.

### 2.2 The three login methods

**(a) Email + "passkey".** The "passkey" is a **user-typed secret string, not WebAuthn**. `appKey = PBKDF2-HMAC-SHA256(passkey, salt = SHA-256("appId:email"), c = 600_000, dkLen = 32)` ([src/core/crypto.ts:30-32](src/core/crypto.ts#L30-L32)). Wallets are generated and AES-256-GCM-encrypted client-side. The server stores `authPublicKey = ed25519_pub(SHA-256("ttc-auth-v1:" + appKey))` — the public half only ([src/client/authKey.ts:14-21](src/client/authKey.ts#L14-L21)) — and login is an ed25519 signature over a server-issued challenge.

**(b) Web3 wallet.** Server-side verification is **Solana ed25519 only**. Two signatures with distinct purposes ([src/client/authClient.ts:288-307](src/client/authClient.ts#L288-L307)): one over the random challenge (sent to the server), one over a **fixed, appId-bound** message whose SHA-256 becomes the app key and which never leaves the browser. **C-1 is a flaw in this handshake.**

**(c) WebAuthn biometric.** Two distinct features that share a word: *biometric-primary* (the passkey secret **is** the app key) and *biometric unlock* (an HKDF-derived key **wraps** the account's existing app key into an IndexedDB blob). Each has a PRF path and a **gate** fallback — see H-1/H-2.

### 2.3 Assets, ranked

1. **Wallet private keys (plaintext)** — bearer control of on-chain funds, irreversible.
2. **App key** — decrypts every wallet the account holds. Memory-only by design.
3. **The user's passkey** — deterministically regenerates the app key on any device, forever. Not rotatable.
4. **Session token** — bearer credential; grants `user-data` and `import-wallet`, *not* decryption.
5. **Encrypted wallet blobs + email→publicKey index** — offline-attackable material and a user graph.

### 2.4 Trust boundaries and actors

| Boundary | Crossing | Enforced by |
|---|---|---|
| Browser → server | HTTP body/headers, fully attacker-controlled | `validateEmail` / `validatePublicKey` / `validateAppId` / `validateWallets` |
| Server → storage | Keys built from validated inputs | `appScoped` + `APP_ID_RE` |
| App ↔ app (multi-tenant) | `appId` from request body/header | `allowedAppIds` (**off by default** — M-11) |
| Signing site ↔ wallet | The message text shown to the user | **Nothing — see C-1** |

Actors assumed: anonymous internet; authenticated user; **DB-read attacker** (leaked backup, replica, world-readable Supabase `public` schema); **XSS on the integrating origin**; malicious co-tenant app; phishing site.

### 2.5 Claims the SDK makes, and the code each depends on

| Claim | Load-bearing code | Holds? |
|---|---|---|
| Server never sees plaintext key material | [wallet.ts:37-58](src/client/wallet.ts#L37-L58) — encrypt before return | ✅ Yes |
| Storage never sees a raw session token | [session.ts:55-62](src/server/session.ts#L55-L62) — digest is the key | ✅ Yes |
| App key is memory-only | [client/session.ts:62-99](src/client/session.ts#L62-L99) — `Symbol.for` global | ✅ Yes (but M-8) |
| Biometric secret is safe at rest | [webauthn.ts:202-247](src/client/webauthn.ts#L202-L247) | ❌ **No — H-1** |
| Cross-app key isolation via `appId` | [core/index.ts:29](src/core/index.ts#L29), [crypto.ts:30](src/core/crypto.ts#L30) | ❌ **No — C-1, M-10** |
| Non-custodial | The whole chain above | ⚠️ **Conditional — C-1, H-3** |

---

## 3. Critical findings

### C-1 — Web3 login and app-key messages are not bound to the verifying origin, enabling signature relay and remote wallet decryption

**Severity: Critical** · `[first-hand]` `[adversarial]` · [src/core/index.ts:9](src/core/index.ts#L9), [src/client/authClient.ts:298](src/client/authClient.ts#L298), [src/server/signature.ts:43](src/server/signature.ts#L43)

**The defect.** The only thing a Web3 wallet signs to prove ownership is:

```ts
// src/core/index.ts:9-11
export function walletLoginMessage(challenge: string): string {
  return `Sign this message to verify wallet ownership: ${challenge}`;
}
```

No origin. No appId. No site name. Every deployment of the SDK produces the identical byte string. Meanwhile the *app-key* message is appId-bound — but the appId comes from the **client's own config**, so an attacker simply sets it:

```ts
// src/core/index.ts:29-31
export function walletAppKeyMessage(appId = "ttc"): string {
  return `${WALLET_APP_KEY_MESSAGE}\n\nApp: ${appId}`;
}
```

And `/challenge` is unauthenticated and accepts an arbitrary `publicKey` ([routes.ts:202-239](src/server/routes.ts#L202-L239)) — a Solana address is public on-chain, so anyone can mint a challenge for anyone.

**Attack.**

1. Attacker runs `evil.app`, configuring the SDK with `config.appId = "victim.app"`.
2. Victim clicks "Connect wallet" on `evil.app`.
3. `evil.app`'s backend POSTs `{appId:"victim.app", publicKey:<victim address>}` to `victim.app/api/auth/challenge` → challenge `C`.
4. `evil.app` prompts the wallet for two signatures — exactly what a legitimate login looks like:
   - `"Sign this message to verify wallet ownership: C"` — **names no site at all**
   - `walletAppKeyMessage("victim.app")` — names `victim.app`, on a page that is not `victim.app`
5. Attacker relays `(publicKey, sig1, C)` to `victim.app/api/auth/login-wallet` → **valid session as the victim**.
6. Attacker computes `SHA-256(hex(sig2))` → **the victim's app key for `victim.app`** → fetches the encrypted wallet bundle via the session from step 5 → **decrypts every private key**.

Step 6 is the part that makes this critical rather than high: it is not session theft, it is **key theft**. The victim's funds move.

**Why the existing defences do not stop it.** The challenge is single-use and TTL-bound — irrelevant, the attacker obtains a fresh legitimate one. The signature is genuine, so `verifySolanaSignature` correctly returns `true`. `appId` domain separation works exactly as designed; it just separates by a value the *attacker* chooses, not by the origin doing the verifying.

**Recommendation.** Bind both messages to the verifier's own domain, taken from server configuration and never from the request. Adopt a SIWE / EIP-4361-style envelope:

```
victim.app wants you to sign in with your Solana account:
<address>

URI: https://victim.app
Nonce: <challenge>
Issued At: <timestamp>
```

The server must rebuild the expected preimage from **its own** `config.appId` and a server-configured canonical origin. For the app-key message, add the origin alongside the appId.

**Compatibility cost — significant, and it must be planned.** Changing the app-key message changes every derived app key, so **existing encrypted wallets stop decrypting**. This needs a migration: on next successful login, derive under both the old and new messages, re-encrypt the bundle under the new key, and write it back. The login message can change immediately (it is not key-derivation input). Ship the login-message fix first; stage the app-key migration.

---

## 4. High findings

### H-1 — Gate-mode passkey secret is recoverable by any same-origin script, with no biometric ceremony

**Severity: High** · `[first-hand]` · [src/client/webauthn.ts:200-247](src/client/webauthn.ts#L200-L247)

The file documents its guarantee as: *"any script on the origin sees only the opaque key handle + IV + ciphertext, never the plaintext."* That guarantee does not hold. `gateStore` persists a `GateRecord { cryptoKey, iv, ciphertext }` into IndexedDB, where `cryptoKey` is a **non-extractable** AES-GCM key. Non-extractable prevents exporting the raw bytes — it does **not** prevent *using* the key. Any same-origin script can open `ttc_passkey_store`, read the record, and call `crypto.subtle.decrypt({name:"AES-GCM", iv: rec.iv}, rec.cryptoKey, rec.ciphertext)` to recover the plaintext secret. No WebAuthn assertion is involved.

The biometric assertion in `derivePasskeySecret` ([webauthn.ts:123-151](src/client/webauthn.ts#L123-L151)) runs *before* `gateLoad`, in ordinary control flow. It gates the SDK's own code path, not the data.

**Impact.** For a **biometric-primary** account the gate secret **is** the app key → XSS or a malicious extension yields every wallet private key, persistently and offline. For **biometric unlock**, the same reasoning applies to the wrapped blob in H-2's path.

**Recommendation.** The secret must be cryptographically bound to the assertion, not merely sequenced after it. Without PRF there is no honest way to do this in the browser — so the correct fix is to **remove gate mode** and surface "this device cannot protect your key at rest; PRF is required" to the caller. If gate mode is retained as a convenience tier, it must be documented as *"no at-rest protection against same-origin script execution"* and must never be entered silently (H-2).

### H-2 — Silent PRF → gate downgrade

**Severity: High** · `[first-hand]` · [src/client/webauthn.ts:96](src/client/webauthn.ts#L96)

```ts
const mode: "prf" | "gate" = config.preferPrf && ext.prf?.enabled ? "prf" : "gate";
```

If the authenticator does not report PRF, the SDK falls back to gate mode and returns normally. Nothing informs the caller, the user, or the UI that the security tier just changed from "secret never at rest" to "secret at rest and XSS-recoverable" (H-1). `preferPrf` defaults to `true` ([config.ts:178](src/core/config.ts#L178)), so the name suggests a preference while the failure is silent.

**Recommendation.** Make the downgrade explicit: return the resolved mode to the caller, add a `requirePrf?: boolean` config that throws rather than degrading, and have the shipped UI surface the tier. `PasskeyRegistration.mode` is already persisted, so the information exists — it simply is not acted on.

### H-3 — No strength floor on the passkey that encrypts every wallet

**Severity: High** · `[adversarial]` (confirmed twice, independently) `[first-hand]` · [src/ui/EmailMethod.tsx:166](src/ui/EmailMethod.tsx#L166), [src/core/crypto.ts:23](src/core/crypto.ts#L23)

`deriveAppKeyFromPasskey` takes `passkey: string` straight into PBKDF2 with no length or entropy check, at any layer. The shipped UI's submit button is guarded only by `disabled={busy || !email || !passkey}` — **any non-empty string is accepted**. The strong-passkey generator (`generateStrongPasskey`, [ui/passkey.ts](src/ui/passkey.ts)) exists and is correct, but is **opt-in** via the `passkeyGenerator` prop and hidden by default.

The server cannot compensate: it never sees the passkey by design. Enforcement is only possible client-side, and there is none.

**Attack.** An attacker with database read access (leaked backup, replica, world-readable Supabase `public` schema — the exact scenario [postgres.ts:108-121](src/storage/sql/dialects/postgres.ts#L108-L121) is written to prevent) obtains the encrypted wallet blob, the email, and the pinned iteration count. The email and `appId` fully determine the PBKDF2 salt. The attacker then brute-forces offline: guess → derive → attempt AES-GCM decrypt → the auth tag is an exact oracle. Against a human-chosen password, 600k PBKDF2-SHA256 iterations buys hours, not security. **The wallets are stolen.**

**Recommendation.** Enforce a floor before derivation — reject below ~64 bits of estimated entropy, and make the generator the default path rather than an opt-in prop. This is a breaking change for existing weak-passkey accounts; pair it with a prompted re-encryption on next login. Document unambiguously that passkey strength *is* the wallet's security parameter.

### H-4 — Unauthenticated, unbounded, permanent storage growth via `/register`

**Severity: High** · `[first-hand]` · [src/server/routes.ts:277](src/server/routes.ts#L277), [routes.ts:182-197](src/server/routes.ts#L182-L197)

`/register` is unauthenticated. For an email account it requires no signature and no proof of possession of either key. The rate-limit bucket is `identifier: body.email ?? body.publicKey` — **both attacker-chosen**, so rotating the email evades the per-target limit entirely. The IP leg is skipped unless `trustProxyHeaders` is true, and it defaults to **false** ([config.ts:163](src/core/config.ts#L163)).

`validateWallets` caps a request at 16 wallets × 8,192-byte `encryptedSecret` ≈ **131 KB per request**, and `maxWalletsPerUser` (64) is enforced only in `importWallet` ([routes.ts:534](src/server/routes.ts#L534)), never in `register` or `connectWallet`. Records are permanent — no TTL, no sweeper.

**Attack.** Loop: generate a random valid base58 key and a random email, POST `/register` with 16 maximal wallets. Each request writes ~131 KB permanently, with no effective throttle. This fills the integrator's database, and on metered storage it is a billing attack.

**Recommendation.** Enforce `maxWalletsPerUser` in `register`/`connectWallet`. Add an IP or proof-of-work leg that does not depend on `trustProxyHeaders`. Consider requiring a challenge-signature for email registration too — the client already holds the auth keypair at that point, so this is cheap (and it also closes H-5).

### H-5 — `/register` binds an identity public key with no proof of possession, and email ownership is never verified

**Severity: High** · `[first-hand]` · [src/server/routes.ts:298-315](src/server/routes.ts#L298-L315)

For `authMethod !== "wallet"`, registration requires only that `authPublicKey` be well-formed hex. Nothing proves the caller controls the corresponding private key, the identity `publicKey`, or the email address. Only the `authMethod === "wallet"` branch verifies a signature.

**Two distinct attacks:**

1. **Permanent targeted account denial.** The attacker registers `victim@example.com` with their own `authPublicKey`. The victim's later registration hits the 409 collision check ([routes.ts:298-301](src/server/routes.ts#L298-L301)); the client's "auto" mode then falls back to `loginWithEmail`, which signs with the auth key derived from the *victim's* passkey — which does not match the attacker's stored `authPublicKey`. The victim receives 401 forever. They cannot register and cannot log in, and there is no recovery path in the SDK.
2. **Wallet-address squatting.** The attacker registers with the victim's real, on-chain Solana address as the identity `publicKey`. `search-wallet` then reports it exists, and when the victim later connects that wallet they are logged into a record whose `email`, `authPublicKey`, and `wallets` are all attacker-controlled.

**Recommendation.** Require a challenge-signature over `authPublicKey` for email/biometric registration (the client can already produce it). Add an email-verification hook, or document loudly that the SDK performs none and the integrator must. For (2), reject a `publicKey` that is not proven — this is the same fix.

### H-6 — Anyone can invalidate a victim's in-flight login challenge

**Severity: High** · `[first-hand]` · [src/server/challenge.ts:14](src/server/challenge.ts#L14), [src/server/routes.ts:234](src/server/routes.ts#L234)

Challenges are stored at exactly one slot per `(appId, publicKey)` — `putChallenge` overwrites unconditionally, and `/challenge` is unauthenticated and accepts any `publicKey` or `email`.

**Attack.** The victim's client fetches challenge `C1` and begins deriving its app key — which at `securityLevel: 2` takes ~7 seconds of PBKDF2. Within that window the attacker POSTs `/challenge` for the same identity, replacing the slot with `C2`. The victim submits a signature over `C1`; `consumeChallenge` takes `C2`, the constant-time compare fails, and the victim gets `401 Invalid credentials`. Repeating at low request rate locks a named user out of their own wallet indefinitely, from an unauthenticated endpoint.

The slow PBKDF2 that protects the passkey is precisely what widens this race window.

**Recommendation.** Allow multiple concurrent challenges per identity (store a small set, consume by value), or do not overwrite an unexpired challenge. Both preserve single-use semantics.

### H-7 — The `unknown` IP bucket becomes a global lockout when `trustProxyHeaders` is enabled without a proxy

**Severity: High** · `[first-hand]` · [src/server/routes.ts:127-141](src/server/routes.ts#L127-L141), [src/server/http.ts:25-37](src/server/http.ts#L25-L37)

`clientIp()` returns the literal string `"unknown"` when no `x-forwarded-for` and no `x-real-ip` is present. `rateLimited` gates on the IP bucket whenever `config.trustProxyHeaders` is true — with no check that a usable IP was actually derived:

```ts
if (config.trustProxyHeaders) {
  const ip = await checkRateLimit(store, { endpoint: "ip", identifier: clientIp(req, true, config.trustedProxyHops) }, config.rateLimit);
  if (!ip.allowed) return error("Rate limit exceeded", 429);
}
```

If an integrator sets `trustProxyHeaders: true` but requests arrive without those headers (direct origin access, a health-check path, a misconfigured or bypassed CDN, local/staging), **every user shares the single `"unknown"` bucket**. At the default 10 requests / 60 s, one client — or ordinary traffic — locks out the entire deployment.

The code comment at [routes.ts:117-123](src/server/routes.ts#L117-L123) shows the authors identified exactly this hazard (audit "H5") and handled it for the `trustProxyHeaders: false` case, but the enabled case retains it.

**Recommendation.** Skip the IP leg whenever `clientIp()` yields `"unknown"`, regardless of the flag — the per-target bucket still applies. Have `clientIp` return `null` rather than a sentinel string so the condition is unmissable.

---

## 5. Medium findings

| ID | Finding | Location | Tag |
|---|---|---|---|
| **M-1** | **Rate-limit buckets key the raw email while lookup normalizes it.** `resolvePublicKeyByEmail` applies `normalizeEmail` (lowercase+trim), but the bucket uses `body.email` verbatim. `Victim@x.com`, `victim@x.com`, ` victim@x.com` are one account but *N* buckets — the per-account throttle divides by case permutations. | [routes.ts:377](src/server/routes.ts#L377) | `[first-hand]` |
| **M-2** | **Session revocation is a non-atomic read-modify-write.** Two concurrent logins both read the old `authTokenHash`, both delete it, both mint sessions; last write wins. The loser's session stays valid in storage for its full TTL but is no longer referenced, so the next login cannot revoke it. The documented "single active session" guarantee does not hold under concurrency. | [session.ts:50-71](src/server/session.ts#L50-L71) | `[adversarial]` `[first-hand]` |
| **M-3** | **`putUser` rewrites the whole blob from a stale snapshot.** Every write is a full-record overwrite with no version or CAS, so a concurrent `importWallet` and `issueSession` silently lose one another's changes — including newly imported wallets. | [store.ts:200](src/storage/store.ts#L200), [session.ts:70](src/server/session.ts#L70) | `[adversarial]` |
| **M-4** | **Registration's email-collision check is TOCTOU.** `resolvePublicKeyByEmail` then `persistUser` is check-then-act with no uniqueness constraint on the KV path; two concurrent registrations for one email both pass, and the second `hset` overwrites the index — orphaning the first account. (The SQL backend's `PRIMARY KEY (email, app_id)` makes this structurally safe; the KV backend does not.) | [routes.ts:298](src/server/routes.ts#L298) | `[first-hand]` |
| **M-5** | **SQLite driver: concurrent `transaction()` calls collapse into one shared transaction**, and `depth` is incremented outside the `try/finally`, so one failed `BEGIN` permanently corrupts the depth counter. Atomicity guarantees that `takeChallenge` depends on are voided. | [sql/drivers.ts:177-188](src/storage/sql/drivers.ts#L177-L188) | `[candidate]` |
| **M-6** | **Rate limiter fails open on an empty `RETURNING`.** `Number(rows[0]?.count ?? 1)` treats "no row returned" as "first hit of the window" — permitting the request. Invariant 3 of the store contract is fail-**closed**. | [sql/engine.ts:267](src/storage/sql/engine.ts#L267) | `[candidate]` |
| **M-7** | **Supabase `public`-schema guard is a case-sensitive exact match.** `schema === "public"` misses `"PUBLIC"` / `"Public"`, which Postgres folds to `public` for unquoted identifiers — bypassing the guard that prevents world-readable auth tables. | [postgres.ts:110](src/storage/sql/dialects/postgres.ts#L110) | `[candidate]` |
| **M-8** | **The hot app key is reachable via a publicly-named global.** The vault hangs off `Symbol.for("tetrac.vault")` with mutable fields; the slot is `writable:false` but `configurable:true`, and `autoLockMs` / `lockOnHide` are plain mutable properties. Same-origin script can read the plaintext app key or disable auto-lock. Mitigates to "XSS is already fatal", but it removes the defence-in-depth the memory-only design is meant to provide. | [client/session.ts:62-99](src/client/session.ts#L62-L99) | `[first-hand]` |
| **M-9** | **Biometric-unlock blob is not bound to an account, appId, or session.** `unlockViaBiometric` arms whatever key the blob yields, with no check that it belongs to the currently-identified account; `unlock()` without `validateWith` never validates. Re-enrollment and logout also orphan blobs in IndexedDB (`purge` tracks a single credential via one localStorage marker). | [biometricUnlock.ts:183-234](src/client/biometricUnlock.ts#L183-L234) | `[candidate]` |
| **M-10** | **Default `appId: "ttc"` voids the cross-app domain separation the crypto layer is built on.** The client warns on construction ([authClient.ts:123-129](src/client/authClient.ts#L123-L129)) but the server does not, and nothing refuses to boot. Two deployments left at the default derive **identical app keys** from the same (email, passkey). | [config.ts:155](src/core/config.ts#L155) | `[first-hand]` |
| **M-11** | **`allowedAppIds` defaults to `undefined`** — any well-formed `appId` is accepted, so on a shared database an attacker can mint arbitrary tenant namespaces (storage bloat) and probe for existing ones. The doc string calls the allowlist "STRONGLY recommended in production"; nothing enforces it. | [config.ts:82](src/core/config.ts#L82) | `[first-hand]` |
| **M-12** | **No `Cache-Control` / `Vary` on any response.** `GET /user-data` returns the full user record (including every encrypted wallet blob) with only `content-type` set. Behind a shared cache or CDN that caches 200s by URL, one user's record can be served to another. | [http.ts:3-8](src/server/http.ts#L3-L8) | `[candidate]` |
| **M-13** | **`README.md`, `SECURITY.md` and `CHANGELOG.md` are all 0 bytes** in the published package. For an SDK that holds wallet keys this means: no vulnerability-disclosure policy, no integrator security guidance, and no way to communicate that `appId`, `allowedAppIds`, passkey strength, and `trustProxyHeaders` are security-critical. Several findings here (M-10, M-11, H-3, H-7) are *only* mitigable by the integrator, who is told nothing. | `SECURITY.md`, `README.md` | `[first-hand]` |
| **M-14** | **Ledger app key is firmware-dependent.** The signer cascades over off-chain envelope candidates and the app key is `SHA-256(sig)`; a firmware update that changes which envelope the device accepts changes the signature, and therefore **changes the derived app key** — permanently locking the user out of wallets encrypted under the old one. | [ledger/solanaSigner.ts:83](src/ledger/solanaSigner.ts#L83) | `[candidate]` |

---

## 6. Unverified candidates

These were reported with quoted evidence by a discovery agent, but the adversarial verification pass did not reach them. **They are leads.** Each should be reproduced before being acted on or dismissed.

**Server / routes:** type confusion on `email` (a JSON array passes `validateEmail`, then throws inside `normalizeEmail`); `EncryptedWallet.role` has no length bound while every sibling field does; account enumeration across distinct emails is unlimited under default config; `logout` silently no-ops on a wrong-but-well-formed token while still returning `200 {ok:true}`; `bindSessionToUserAgent` fails open when a request carries no User-Agent; `signature`/`challenge` are unbounded strings parsed before rate limiting; no request-body size limit anywhere.

**Next.js binding:** prototype-chain route dispatch — `postRoutes[await actionOf(ctx)]` resolves inherited `Object.prototype` members, so `POST /api/auth/constructor` (and `valueOf`, `toString`, …) invokes a non-handler and returns a non-`Response`. *My own reading suggests this yields a 500, not an auth bypass — low severity, but it should still use a null-prototype map or `Object.hasOwn`.* ([next/routes.ts:41](src/next/routes.ts#L41))

**Crypto:** `appKeyToBytes` silently maps non-hex characters to `0x00` and accepts 16/24-byte keys (`[adversarial]` confirmed as low); AES-GCM is not key-committing, so `unlock()` without `validateWith` cannot distinguish a wrong key; `decryptSecret` decodes base64url outside its `try`, leaking a raw `DOMException`; no AAD binding ciphertext to chain/role (two verifiers **refuted** the security impact of this one).

**Signatures:** small-order ed25519 public keys accepted; ed25519 malleability — tweetnacl accepts `(R, S+L)`, so a login signature is not a canonical identifier. Both are `[candidate]`; neither is exploitable for forgery on its own given the single-use challenge.

**Storage:** `MemoryAdapter` is production-usable with no runtime guard; KV rate-limit self-heal fires once per window; `keyPrefixes` are integrator-overridable with no ambiguity check; conformance suite never exercises the `appId`-omitted bucket shape; `sweepExpired` is never scheduled, so SQL deployments retain expired sessions, challenges, and **rate-limit rows containing emails and IPs** indefinitely — a data-retention obligation, flagged in the code's own comments.

**Postgres:** the `schema` option is interpolated raw into every statement and the generated DDL (integrator-controlled, not attacker-controlled — but it should be quoted); generated DDL emits no RLS or `REVOKE`, so Supabase protection is schema-placement only.

**Client / UI:** `ExportKeyPanel` re-invokes `onReveal` with the plaintext key on every parent re-render, and its advertised clipboard auto-wipe fails silently and is never cancelled; `useAuth().reauthenticate` arms an unvalidated app key; `AuthProvider` freezes options at mount, so a changed `appId` keeps deriving keys under the old one; the client hardcodes `ttc-auth-token` / `ttc-public-key` while the server reads `config.sessionHeader` / `config.publicKeyHeader` — renaming the headers breaks auth.

**Supply chain:** no npm provenance and `dist/` is gitignored, so the published tarball is not reproducible from the repo; `prepublishOnly` runs only the build, so a release can ship code that never passed typecheck or tests; the CI security-audit step is `continue-on-error: true` and reportedly failing; unbounded peer ranges (`better-sqlite3: ">=9"`, `next: ">=14"`, `react: ">=18"`); a published CJS bundle `require()`s an ESM-only dependency; `docker-compose.test.yml` publishes Postgres and MySQL with password `pw` on all host interfaces.

---

## 7. What this codebase gets right

Worth stating plainly, because it is unusual:

- **SQL is uniformly parameterised**, with expiry filtered on every read path (`expires_at > ?`), atomic `DELETE … RETURNING` for challenge consumption, and a `FOR UPDATE` transaction on MySQL where `RETURNING` is unavailable. [sql/engine.ts](src/storage/sql/engine.ts)
- **The rate-limit `CASE` upsert** correctly makes an expired counter start a fresh window — the permanent-lockout bug this class of code almost always has is explicitly designed out, and tested.
- **Session tokens are persisted only as SHA-256 digests**, with a correct and well-argued justification for why a bare hash (not a KDF) is right for a 256-bit random token.
- **Sensible refusals:** production boot fails rather than falling back to an ephemeral localhost store ([resolve.ts:47-53](src/storage/resolve.ts#L47-L53)); Postgres preflight refuses the `public` schema because of Supabase's PostgREST exposure ([postgres.ts:110-121](src/storage/sql/dialects/postgres.ts#L110-L121)).
- **The Solana off-chain envelope is correctly domain-separated** (`0xFF "solana offchain"`), so a login signature cannot be confused with a transaction signature — a real risk this design avoids.
- **`appId` is validated to exclude the `:` key separator** before it can reach a storage key, closing the namespace-escape class.
- **Verify-first, penalise-on-failure** ordering means a junk signature cannot burn a victim's pending challenge, and a valid login is never throttled by an attacker's failed attempts.
- **No `Math.random`, no `eval`, no `innerHTML`, no `dangerouslySetInnerHTML`** anywhere in `src/`. One runtime dependency (`@noble/hashes`).
- **The code documents its own prior audit findings** (`audit F3`, `F8`, `CRYPTO-2`, `H5`, `WI-5`, `AUTHSESSION-3`, `CLIENTVAULT-7`) with the reasoning preserved, and `tests/` encodes them as regressions.

---

## 8. Remediation roadmap

### Must fix before the next release

1. **C-1** — Ship origin binding for `walletLoginMessage` immediately (no migration needed). Plan and stage the app-key message migration separately, with dual-derivation re-encryption on next login. *This is the finding that breaks the product promise.*
2. **H-2** — Stop degrading silently. Return the resolved mode; add `requirePrf`. One-line-ish change, and it is the precondition for honestly assessing H-1.
3. **H-1** — Remove gate mode, or document it as offering no at-rest protection against same-origin script execution. Do not leave the current comment, which claims a guarantee the code does not provide.
4. **H-4 / H-5** — Enforce `maxWalletsPerUser` in `register` and `connectWallet`, and require a challenge-signature for email/biometric registration. One change closes both the storage-growth and the squatting/lockout attacks.
5. **H-7** — Skip the IP rate-limit leg when `clientIp()` yields no real address. Have `clientIp` return `null` instead of `"unknown"`.
6. **M-13** — Write `SECURITY.md` (disclosure policy) and a `README` security section. Several findings are integrator-mitigable only, and the integrator is currently told nothing.

### Should fix

7. **H-3** — Passkey entropy floor + generator-by-default. Breaking for weak existing accounts; pair with prompted re-encryption.
8. **H-6** — Allow concurrent challenges per identity, or refuse to overwrite an unexpired one.
9. **M-1** — Key rate-limit buckets on `normalizeEmail(email)`. Two-line fix.
10. **M-10 / M-11** — Refuse to boot on `appId === "ttc"` in production; consider defaulting `allowedAppIds` to `[config.appId]`.
11. **M-2 / M-3 / M-4** — Introduce a CAS/version field on `UserData` so writes cannot silently lose each other, and add a uniqueness constraint on the KV email index.
12. **M-5 / M-6 / M-7** — Reproduce and fix the SQLite transaction nesting, the fail-open `?? 1`, and the case-sensitive schema guard.

### Hardening

13. M-8 (harden the vault global), M-9 (bind unlock blobs to an account), M-12 (`Cache-Control: no-store` on all authenticated responses), M-14 (persist the Ledger envelope variant alongside the account), plus the §6 candidates once triaged.
14. Schedule `sweepExpired` — expired rate-limit rows contain emails and IPs, and nothing currently deletes them.
15. npm provenance, `prepublishOnly` running typecheck + tests, and making the CI security-audit step blocking.

---

## 9. Methodology and coverage

**Approach.** 13 parallel discovery agents, one per dimension — crypto primitives, session lifecycle, server routes, signature verification, rate limiting/DoS, SQL storage, KV storage, client vault, WebAuthn/PRF, framework integration, hardware wallet, config/defaults, supply chain. Each was instructed to read actual source, quote verbatim evidence, and grep `tests/` first to avoid re-reporting already-fixed issues. Findings then entered a two-lens adversarial verification pass (code-truth and exploitability), each instructed to default to *refuted*.

**Coverage.** All 62 files in `src/` were assigned to at least one dimension. I additionally read first-hand: `core/crypto.ts`, `core/config.ts`, `core/index.ts`, `core/offchainMessage.ts`, `server/routes.ts`, `server/session.ts`, `server/signature.ts`, `server/rateLimit.ts`, `server/challenge.ts`, `server/http.ts`, `server/keys.ts`, `storage/store.ts`, `storage/resolve.ts`, `storage/sql/engine.ts`, `storage/sql/dialects/postgres.ts`, `client/authClient.ts`, `client/session.ts`, `client/wallet.ts`, `client/webauthn.ts`, `client/biometricUnlock.ts`, `client/authKey.ts`, `next/routes.ts`.

**Known gaps in this audit.**
- The adversarial verification pass is **~8% complete** (19 of 240 verdicts). Most `[candidate]` findings are unvalidated.
- The **completeness critic never ran** — the sweep for missed issue classes (TOCTOU, unicode/homoglyph normalization on email, clock skew, fail-open `catch` blocks, cross-subsystem seams) did not happen. I noted one such case unprompted during review: `normalizeEmail` is `toLowerCase().trim()` with **no Unicode normalization**, so `K` (U+212A KELVIN SIGN) lowercases to `k` and collides with an ASCII address in the index. Worth a targeted look.
- **No dynamic testing.** No exploits were executed; every finding is from static reading. The `[first-hand]` tag means I verified the code path, not that I ran an exploit.
- `dist/` was inspected only for packaging concerns, not decompiled and diffed against `src/`.

**Recommended next step.** Re-run the verification pass over the §6 candidates when API capacity allows, then build proof-of-concept tests for C-1 and H-1 — both are demonstrable in a Jest/jsdom harness, and both deserve a regression test alongside the existing `tests/audit-*.test.ts` suite.
