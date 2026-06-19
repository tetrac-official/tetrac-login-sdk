# Cryptography Specification — `@tetrac/login-sdk`

This is the authoritative description of the SDK's cryptographic design, intended for auditors and
integrators. Every primitive, parameter, and wire format below is traceable to source; file:line
references point at the implementation. If this document and the code ever disagree, **the code is
correct and this document is the bug** — please file a report.

- Primitives library: **[`@noble/hashes`](https://github.com/paulmillr/noble-hashes)** (`sha256`,
  `pbkdf2`, `hkdf`) + **Web Crypto `SubtleCrypto`** (AES-256-GCM, HKDF) + **`tweetnacl`** (ed25519) +
  `@solana/web3.js` (Solana key parsing) + `viem` (EVM keygen).
- **`crypto-es` is not used** and is not a dependency.
- All randomness comes from `crypto.getRandomValues`; there is **no** `Math.random` fallback
  ([`src/core/crypto.ts:96-106`](../src/core/crypto.ts#L96-L106)).

---

## 1. Primitives at a glance

| Purpose | Primitive | Parameters |
|---|---|---|
| Email/passkey app-key KDF | PBKDF2-HMAC-**SHA-256** | iterations per `securityLevel` (default 600k), `dkLen=32` |
| Web3 app-key KDF | SHA-256 over a fixed signed message | — |
| Secret (private-key) encryption | **AES-256-GCM** (Web Crypto, AEAD) | 96-bit random IV, 128-bit tag |
| Biometric-unlock key wrap | HKDF-SHA-256 → AES-256-GCM | salt = credentialId bytes, `info="ttc-biometric-unlock-v1"` |
| Account auth (email/biometric) | ed25519 (`tweetnacl`) | seed = SHA-256(`"ttc-auth-v1:"`+appKey) |
| Web3 auth | ed25519 (Solana, `tweetnacl`) | over the login message |
| Challenge / session token | CSPRNG | 256-bit (32 bytes), hex |
| Secret comparison | constant-time XOR-accumulate | `timingSafeEqual` |

---

## 2. App-key derivation

The **app key** is a 256-bit (64-hex-char) secret that encrypts a user's wallet private keys. It is
derived client-side, is **never sent to the server**, and is held **memory-only** (see §6). There are
three derivations, one per auth method.

### 2.1 Email / passkey — PBKDF2

[`deriveAppKeyFromPasskey`](../src/core/crypto.ts#L23-L33):

```
salt   = SHA-256( utf8( `${appId}:${email.toLowerCase().trim()}` ) )      // 32 bytes
appKey = hex( PBKDF2-HMAC-SHA256( passkey, salt, c = iterations, dkLen = 32 ) )
```

- **Iterations** come from `securityLevel` and are **pinned per user** at registration
  (`UserData.pbkdf2Iterations`), so retuning the default never orphans existing accounts
  ([`src/core/config.ts:44-48`](../src/core/config.ts#L44-L48)):

  | `securityLevel` | iterations | note |
  |---|---|---|
  | 1 | 100,000 | below OWASP 2023 — legacy/compat only |
  | **2** | **600,000** | **default** — OWASP 2023 minimum |
  | 3 | 1,000,000 | future-proof, highest latency |

- **`appId` domain separation:** `appId` is mixed into the salt, so the same `(email, passkey)` derives a
  **different** app key per deployment. Default `"ttc"` provides **no** isolation — override per
  deployment ([`src/core/config.ts:50-65`](../src/core/config.ts#L50-L65)).
- Login re-derives the same key by fetching the pinned iteration count with the challenge; legacy accounts
  with no pinned count fall back to 100k ([`src/client/authClient.ts:207-221`](../src/client/authClient.ts#L207-L221)).

### 2.2 Web3 wallet — SHA-256 of a fixed signature

The wallet produces **two** signatures with distinct purposes
([`src/client/authClient.ts:232-245`](../src/client/authClient.ts#L232-L245)):

```
authSig = sign( walletLoginMessage(challenge) )    // over the RANDOM challenge → ownership proof, sent to server
keySig  = sign( walletAppKeyMessage(appId) )        // over a FIXED message → deterministic, stays client-side
appKey  = hex( SHA-256( hex(keySig) ) )             // deriveAppKeyFromSignature
```

- `walletAppKeyMessage(appId)` is constant per app (not the challenge), so the same wallet decrypts on
  every login and device, and is **`appId`-domain-bound**
  ([`src/core/index.ts:18-30`](../src/core/index.ts#L18-L30)).
- The signature never leaves the client; only its SHA-256 hash becomes the key.

### 2.3 Biometric (primary) — WebAuthn PRF / gate secret

The passkey-derived secret **is** the app key directly
([`src/client/authClient.ts:305-325`](../src/client/authClient.ts#L305-L325),
[`src/client/webauthn.ts:118-151`](../src/client/webauthn.ts#L118-L151)):

- **PRF mode (preferred):** `appKey = hex( PRF_output )`, re-derived on each unlock from the
  authenticator's PRF extension (evaluated over a per-credential random 32-byte salt). The secret is
  never stored.
- **Gate mode (fallback, no PRF):** a random 32-byte secret is wrapped under a **non-extractable**
  AES-256-GCM key in IndexedDB and released only after a successful `userVerification` assertion.

---

## 3. Secret (private-key) encryption — AES-256-GCM

Wallet private keys are encrypted under the app key before leaving the browser
([`src/core/crypto.ts:64-93`](../src/core/crypto.ts#L64-L93)).

```
key = importKey("raw", appKeyBytes(32), "AES-GCM")     // appKey hex → 32 raw bytes
iv  = getRandomValues(12 bytes)                         // 96-bit, unique per encryption
ct  = AES-256-GCM.encrypt(iv, key, utf8(plaintext))     // ciphertext || 128-bit auth tag

ciphertext string = b64url(iv) + ":" + b64url(ct)       // e.g. "Yk3…:9fA…"
```

- **Authenticated (AEAD):** decryption verifies the GCM tag; a wrong key or any tampering **throws**. The
  error is generic (`"Decryption failed: wrong key or corrupted ciphertext"`) to avoid an oracle
  ([`src/core/crypto.ts:80-93`](../src/core/crypto.ts#L80-L93)).
- Stored on `EncryptedWallet.encryptedSecret` ([`src/core/types.ts:19-27`](../src/core/types.ts#L19-L27)).
  Solana stores the 64-byte secret as hex; EVM stores the `0x`-prefixed private key.
- There is **no CBC path and no legacy/unauthenticated fallback** — the only at-rest format is the
  authenticated `iv:ct+tag` above.

---

## 4. Biometric unlock (optional layer on any account)

Distinct from §2.3: this **wraps** an account's existing app key so a returning user can re-arm the vault
with Touch/Face ID instead of re-running the full ceremony
([`src/client/biometricUnlock.ts`](../src/client/biometricUnlock.ts)).

```
wrapKey = HKDF-SHA-256( ikm = passkeySecretBytes,
                        salt = b64urlDecode(credentialId),
                        info = "ttc-biometric-unlock-v1" ) → AES-256-GCM key (non-extractable)
blob    = { v:1, iv: 12 random bytes, ciphertext: AES-256-GCM(wrapKey, iv, utf8(appKey)) }   // IndexedDB
```

- The raw PRF/gate secret is **never used directly as an AES key** — it is HKDF-stretched first.
- Unwrapping always requires a **fresh biometric assertion** to re-derive the secret; AES-GCM fails closed
  on tamper or wrong secret.
- The blob lives in IndexedDB (`ttc_passkey_store` / `unlock_blobs`); storage-scraping XSS reads
  ciphertext it cannot unwrap. Purged on `disableBiometricUnlock` and on logout.

---

## 5. Authentication & sessions

### 5.1 Challenge–response (no server-stored passkey hash)

The server **never stores a passkey hash or any passkey-derived secret** — only public keys.

- **Challenge:** 256-bit CSPRNG hex, stored at `challenge:{publicKey}` with TTL `challengeTtlSeconds`
  (**default 300s**), **single-use** via an atomic `getdel` that closes the get-then-delete replay race,
  compared with `timingSafeEqual` ([`src/server/challenge.ts`](../src/server/challenge.ts)).
- **Email / biometric accounts:** the client derives an ed25519 keypair from the app key —
  `seed = SHA-256("ttc-auth-v1:" + appKey)` — signs `authLoginMessage(challenge)`, and the server verifies
  against the stored `authPublicKey` (hex) ([`src/client/authKey.ts`](../src/client/authKey.ts),
  [`src/server/signature.ts:45-58`](../src/server/signature.ts#L45-L58)).
- **Web3 accounts:** the server verifies a **Solana ed25519** signature over `walletLoginMessage(challenge)`
  with `tweetnacl` ([`src/server/signature.ts:24-37`](../src/server/signature.ts#L24-L37)). Web3 accounts
  store no `authPublicKey`.

> **Known limitation (tracked as WI-15):** biometric auth currently verifies a *client-derived* ed25519
> signature, **not** a hardware WebAuthn assertion — the server does not check `origin`, `rpIdHash`, or a
> monotonic `signCount`. See [`audits/v0.3.2-PRD.md`](../audits/v0.3.2-PRD.md).

### 5.2 Sessions

[`src/server/session.ts`](../src/server/session.ts):

- **Opaque bearer token:** 256-bit CSPRNG hex (`generateSessionToken`), stored at `session:{token}` →
  `publicKey` with TTL `sessionTtlSeconds` (**default 14400 = 4h**). No JWT.
- **Single active session:** each login revokes the previous token, so a leaked token can't outlive the
  next login.
- Validated by matching both the token and the public key from the `ttc-auth-token` / `ttc-public-key`
  headers. `logout()` revokes server-side via `POST /logout` (`keepalive`), with the TTL as backstop.
- **Optional UA binding (`bindSessionToUserAgent`, default off):** when enabled, a session stores
  `publicKey|SHA-256(User-Agent)` and `verifySession` rejects (constant-time) a request whose UA hash
  differs or is absent. Enforced per-session, so disabling the flag never un-binds live sessions.
  Defense-in-depth only — the UA is spoofable and a UA change forces re-login.

### 5.3 Rate limiting

Per-target counters (`ratelimit:{identifier}`, e.g. `login:<email>`), incremented with a window TTL
([`src/server/rateLimit.ts`](../src/server/rateLimit.ts)). Client IP is only used when
`trustProxyHeaders` is true; otherwise `x-forwarded-for` is ignored (returns `"unknown"`) so it can't be
spoofed to dodge limits ([`src/server/http.ts:25-37`](../src/server/http.ts#L25-L37)).

---

## 6. Client vault (key-at-rest model)

[`src/client/session.ts`](../src/client/session.ts):

- The app key is **memory-only** — never `sessionStorage`, never `localStorage`, never the network. A
  reload/crash drops it (fresh JS realm), so storage-scraping XSS finds no key at rest.
- It is held on a single cross-bundle instance keyed by `Symbol.for("tetrac.vault")` so every subpath
  bundle (`/client`, `/react`, `/ui`, …) shares one runtime state.
- **Auto-locks** after `autoLockMs` idle (**default 15s**) and on `visibilitychange`→hidden, `freeze`,
  `pagehide`, and bfcache `pageshow` (persisted); a **cross-tab** lock signal (`ttc_lock_signal`) and
  token removal lock sibling tabs. Locked signers throw `VaultLockedError`.
- **Reveal/export re-auth:** `revealSecret()` derives a one-time key from a fresh ceremony and does **not**
  arm the session, so revealing a plaintext key never silently extends the signing window
  ([`src/client/authClient.ts:149-162`](../src/client/authClient.ts#L149-L162)).
- `localStorage` holds only **non-secrets**: the bearer token, public key, email (the PBKDF2 salt input),
  the pinned PBKDF2 iteration count, the lock signal, and the biometric-unlock marker.

---

## 7. Versioned strings & domain separators

Changing any of these changes derived values (a clean break for affected accounts).

| String | Where | Role |
|---|---|---|
| `"ttc-auth-v1:"` + appKey | `authKey.ts` | ed25519 auth-seed prefix (domain separation) |
| `"ttc-biometric-unlock-v1"` | `biometricUnlock.ts` | HKDF `info` for the unlock wrap key |
| `walletAppKeyMessage(appId)` | `core/index.ts` | fixed wallet message → deterministic Web3 app key |
| `walletLoginMessage(challenge)` | `core/index.ts` | Web3 ownership-proof message |
| `authLoginMessage(challenge)` | `core/index.ts` | email/biometric login message |
| `appId` (default `"ttc"`) | `config.ts` | salt + message domain separation per deployment |

---

## 8. What this design deliberately does **not** do

- **No non-extractable app key.** The app key is an exportable hex string by design, because it must be
  deterministically re-derivable across devices to recover non-custodially. (The biometric *wrap* key and
  the *gate* key are non-extractable.)
- **No server-side key custody, escrow, or recovery.** Lose every factor → keys are unrecoverable.
- **No secp256k1/EVM signature verification server-side.** EVM keypairs are internal client-generated
  signing wallets; external **wallet login is Solana-only** by design.
- **No legacy/unauthenticated ciphertext.** Only authenticated AES-256-GCM is read or written.

See [`docs/THREAT_MODEL.md`](./THREAT_MODEL.md) for the threats these choices accept and the integrator
mitigations.
