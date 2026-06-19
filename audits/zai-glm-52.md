# Security Audit — `@tetrac/login-sdk` v0.3.2

**Auditor:** ZCode (GLM-5.2), automated security review
**Date:** 2026-06-19
**Scope:** Full source tree at `package.json` v0.3.2 (`@noble/hashes` core, Web Crypto, tweetnacl,
@solana/web3.js, viem) — `src/core`, `src/client`, `src/server`, `src/storage`, `src/next`,
`src/react`, `src/ui`, plus the test suite and published design docs.
**Goal context (stated by the integrator):** this SDK is intended to **replace Privy / Turnkey
Wallet-as-a-Service** — i.e. it must be defensible as the custody boundary for real funds.
**Method:** static review of every source file + cross-checked against the 179-test suite (green at
audit time) + runtime confirmation of two candidate findings. Every finding cites `file:line`.
**Companion docs:** [`SECURITY.md`](../SECURITY.md), [`docs/CRYPTO_SPEC.md`](../docs/CRYPTO_SPEC.md),
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md), prior audits in this folder.

---

## 0. How to read this report

The two AI audits already in this folder (`agent-ai.md` = "Audit A/B") were written against a *generic*
"SDK of this class" and **the large majority of their findings are already fixed in v0.3.2** (no
`crypto-es`, AES-256-GCM not CBC, 600k-default PBKDF2, memory-only vault, ed25519 signature auth with
no `passkeyHash`). The maintainer PRD ([`audits/v0.3.2-PRD.md`](./v0.3.2-PRD.md)) documents that
reconciliation. **I re-verified those claims against the actual HEAD code** and confirm them — I do
not repeat resolved items as findings. This report carries **only what is genuinely open or newly
observed in the current code**, with severity ratings and concrete patches.

Severity scale: **Critical / High / Medium / Low / Informational**.

---

## 1. Executive summary

**Overall posture: Strong, with one Critical architectural caveat that integrators must not deploy without mitigating.**

The cryptographic core is sound for its stated design:

- Secret encryption is **authenticated AES-256-GCM** via Web Crypto; the GCM tag closes the
  malleability/padding-oracle class entirely (`src/core/crypto.ts:72-93`). There is **no** CBC path.
- App-key derivation is **PBKDF2-HMAC-SHA256** at a per-user-pinned **600k default** with an
  `appId`-domain-separated salt (`src/core/crypto.ts:23-33`, `src/core/config.ts:44-48`).
- The server stores **no passkey-derived secret** — auth is a challenge signature against a stored
  ed25519 public key (`src/server/signature.ts:45-58`). The old `passkeyHash` is gone.
- Challenges are 256-bit, single-use via atomic `getdel` (`src/server/challenge.ts:25-35`).
- Sessions are opaque 256-bit CSPRNG tokens, TTL 4h, **single active session** (login revokes the prior)
  (`src/server/session.ts:59-79`).
- The app key is **memory-only**, auto-locks at 15s idle + on hide/freeze/bfcache + cross-tab
  (`src/client/session.ts`).
- Per-target rate limiting with a correctly-defaulted-off `trustProxyHeaders`
  (`src/server/routes.ts:73-88`, `src/server/http.ts:25-37`).

Against that baseline, the genuine risks are concentrated in **three places**:

1. **CRITICAL (design/integrator-dependent):** **Biometric (WebAuthn) accounts authenticate with a
   client-derived ed25519 key, not a verified hardware assertion.** The server never checks `origin`,
   `rpIdHash`, `signCount`, or attestation. A phishing/lookalike site, a compromised relying party, or
   any XSS can drive the full biometric login flow with a software-derived key — the "biometric"
   guarantee is cosmetic server-side. This is tracked as **WI-15** but its severity is under-rated in
   the roadmap for an SDK that aims to **replace Turnkey**. See [F1](#f1--critical-biometric-webauthn-login-is-not-bound-to-a-hardware-assertion).
2. **HIGH:** The **PBKDF2 iteration count is fully client-controlled at registration** and trusted
   verbatim — an attacker (or a misconfigured/integrating client) can register an email account with
   `pbkdf2Iterations: 1`, deliberately kneecapping that account's offline brute-force resistance with
   **no server floor**. See [F3](#f3--high-server-trusts-client-supplied-pbkdf2-iteration-count-with-no-floor).
3. **MEDIUM:** Several **server authorization/identity gaps** that turn "the SDK" into the
   *only* thing standing between a malicious client and someone else's stored record — most notably
   `import-wallet` appends attacker-chosen ciphertext to a victim's record under a **valid session
   without re-binding ownership**, and `connect-wallet`/`register` let a client claim any string as
   `publicKey`. See [F4](#f4--medium-import-wallet-appends-attacker-controlled-ciphertext-without-ownership-binding) and [F2](#f2--high-no-proof-of-key-control-on-registration-publickey-identity-is-attacker-chosen).

Lower-severity items: an AES key importable as raw bytes + missing additional authenticated data
([F5](#f5--low-aes-gcm-key-is-imported-as-extractable-raw-bytes-no-aad--context-binding)), a non-atomic
rate-limit `incr`+`expire` race on KV ([F7](#f7--low-rate-limit-incr--expire-is-not-atomic-on-kvbackends)), a
`timingSafeEqual` out-of-bounds read ([F8](#f8--low-timingsafeequal-reads-out-of-bounds-on-length-mismatch)), a
client fingerprint `KEY` in `localStorage` that survives `clearSession` ([F9](#f9--low-biometric-reg-descriptor-persisted-in-localstorage-survives-logout)), and several documentation/release-eng items.

**Bottom line:** As a **generic embedded-wallet library** (Solana/EVM key generation + encryption +
signing) the core is production-grade. As a **replacement for a Wallet-as-a-Service** (Turnkey/Privy)
it is **not yet defensible** until F1 (hardware assertion) and F3 (server KDF floor) are closed, and
F2/F4's identity model is hardened. None of the cryptographic primitives are broken; the exposure is
in the **trust boundaries** between client and server.

---

## 2. Detailed findings

### F1 — CRITICAL: Biometric (WebAuthn) login is *not* bound to a hardware assertion

**Location:** `src/client/authKey.ts:13-28`, `src/client/authClient.ts:333-369`, `src/server/signature.ts:45-58`,
`src/server/routes.ts:249-276` (the email/biometric `login` path).
**Severity:** Critical (for the stated Turnkey-replacement use case) / High (as a generic SDK).
**Status:** Known/tracked as **WI-15** ([`audits/v0.3.2-PRD.md`](./v0.3.2-PRD.md) §2) — **re-raised here because the severity is under-stated.**

**Problem.** A "biometric" account's identity is an ed25519 keypair whose seed is
`SHA-256("ttc-auth-v1:" + appKey)`, and `appKey` is the PRF/gate secret. The server authenticates the
user by verifying a signature from that **derived** key over the login challenge — exactly the same
verification it runs for *email/passkey* accounts (`verifyAuthSignature`, `src/server/signature.ts:45-58`).

The server therefore:

- stores **no WebAuthn credential / COSE public key** (`src/core/types.ts:38-56` has no credential field);
- verifies **no attestation** at register (`src/server/routes.ts:171-247`);
- verifies **no `origin`, `rpIdHash`, `signCount`, or `userVerification`** at login;
- and consumes the challenge based purely on the derived-key signature (`src/server/routes.ts:263-276`).

**Impact.** The "biometric" property is enforced **only client-side** (`userVerification: "required"` at
`src/client/webauthn.ts:85,134`). From the server's perspective, any holder of the PRF secret — which is
just `appKey` bytes — can produce a valid login signature. Concrete scenarios that defeat the
biometric guarantee:

1. **Phishing / lookalike relying party.** A malicious site on a sibling domain tricks the user into a
   WebAuthn ceremony scoped to *its* `rpId`. The derived app key is then identical to what the genuine
   app would derive for the same credential inputs on the attacker's `appId`, or the attacker simply
   harvests the PRF/gate secret through their own flow and replays the login signature. There is **no
   `origin`/`rpIdHash` check** to catch this server-side.
2. **XSS on the relying origin.** Any script on the real origin can invoke
   `navigator.credentials.get` (the biometric prompt), obtain the PRF/gate secret via
   `derivePasskeySecret`, and authenticate as the user — *or* simply operate the SDK's own
   `loginWithBiometric`/`sign` while the vault is hot. The memory-only vault limits the *window*, not
   the *capability* (documented residual R1).
3. **Server DB leak.** The stored `authPublicKey` plus ciphertext is enough to mount an offline
   signature oracle; combined with F3 (no KDF floor) the PRF/gate path is the weakest link.

Because the SDK's stated goal is to **replace Turnkey/Privy** — whose entire value proposition is that
authentication is bound to a hardware-attested key with server-verified origin and signCount — this is
the single most important gap. The PRD labels it "High"; for the wallet-as-a-service replacement use
case it is **Critical**.

**Recommendation (mirrors WI-15, with sharper severity).**
- At **register**: collect the WebAuthn attestation object, verify it server-side
  (`@simplewebauthn/server` `verifyRegistrationResponse` against the expected `rpId`/`origin`/challenge),
  and store `{ credentialId, credentialPublicKey, signCount, transports, backupEligible }` on the user
  record (extend `UserData` in `src/core/types.ts`).
- At **login**: verify the assertion object with `verifyAuthenticationResponse` — enforce
  `origin`, `rpIdHash`, **strictly-increasing `signCount`** (clone detection), `userVerification === "required"`,
  and that the signed challenge is the single-use server-issued one.
- Bind the **single-use challenge** into the WebAuthn `clientDataJSON.challenge`, not (only) into a
  parallel derived-key signature, so a stolen assertion can't be replayed against a fresh challenge.

**Proof.** `grep` for attestation/assertion verification returns nothing in `src/server`; the only
signature verifier is the derived-key `verifyAuthSignature` (`src/server/signature.ts:45-58`). The
register handler accepts a bare `authPublicKey` hex with no credential object
(`src/server/routes.ts:189-229`).

---

### F2 — HIGH: No proof-of-key-control on registration; `publicKey` identity is attacker-chosen

**Location:** `src/server/routes.ts:171-247` (`register`), `src/server/routes.ts:47-52` (`validatePublicKey`).
**Severity:** High.

**Problem.** The email/biometric registration path (`authMethod !== "wallet"`) stores a user record
keyed on the **client-supplied `publicKey`** and the **client-supplied `authPublicKey`**, with **no
signature and no proof that the caller controls the derived auth keypair**
(`src/server/routes.ts:227-243`). The only ownership proof in the file is for the wallet path
(`verifySolanaSignature`, `src/server/routes.ts:220-226`). The `validatePublicKey` check is deliberately
loose — any trimmed string ≤128 chars is accepted, including an EVM `0x…` address or another user's
base58 key (`src/server/routes.ts:47-52`).

This is explicitly documented as a structural residual (`SERVERSIDE-5`: "no email ownership proof")
and even has a characterization test that **registers an arbitrary unvalidated `publicKey` with no
proof of control and gets `201`** (`tests/audit-server.test.ts:104-116`).

**Impact.** Two real problems beyond the documented "no email verification":

1. **Identity squatting / collision griefing.** An attacker can pre-register
   `publicKey = <victim's future Solana funds key>` as an *email* account with an `authPublicKey`
   they control. When the victim later connects that wallet, `connectWallet` finds the record already
   exists and **refuses to overwrite** (`src/server/routes.ts:340-356`) — the victim cannot claim their
   own on-chain identity through the SDK, and the squatter holds the `email→publicKey` index.
2. **Email-index squatting.** `register` checks `publicKey` collision then `email` collision
   (`src/server/routes.ts:201-215`), but the email check resolves through `resolvePublicKeyByEmail` —
   both indices are populated from unverified client input. Combined with the (correctly documented)
   absence of email ownership verification, the email namespace is fully attacker-writable.

**Recommendation.**
- Require every registration to prove control of the identity it claims: for email/biometric accounts,
  require the **derived auth keypair to sign the single-use challenge** at register (the server already
  has `verifyAuthSignature`), and consume that challenge — exactly as the wallet path does. Today
  register for email/biometric consumes **no** challenge, so the ceremony is free.
- Tighten `validatePublicKey` by `authMethod`: a Solana identity should match base58 ed25519 length;
  reject `0x`-prefixed strings as a *Solana* identity (the test at `tests/audit-server.test.ts:104-116`
  currently asserts the insecure behavior — flip it when fixed).
- For email accounts, gate registration behind verified email ownership + bot-gating (already an
  integrator obligation, R5; consider documenting a *required* pre-register verify step rather than
  "recommended").

---

### F3 — HIGH: Server trusts client-supplied PBKDF2 iteration count with no floor

**Location:** `src/server/routes.ts:171-247` (`register`, stores `body.pbkdf2Iterations` verbatim),
`src/core/types.ts:53-54` (`pbkdf2Iterations?: number`), `src/server/routes.ts:167-168` (returned to client).
**Severity:** High.

**Problem.** The client picks `securityLevel` and sends the resolved iteration count to the server,
which **pins it verbatim** with no validation (`src/server/routes.ts:240`: `pbkdf2Iterations: body.pbkdf2Iterations`).
There is no lower bound, no range check, and no `Number.isInteger`/`isFinite` check.

```ts
// src/server/routes.ts:240 — stored as-is
pbkdf2Iterations: body.pbkdf2Iterations,
```

A malicious or buggy/integrating client can register an email account with `pbkdf2Iterations: 1` (or
`0`, or `1e9`, or `NaN`). The server dutifully pins it and later returns it so login re-derives with
that same count (`src/server/routes.ts:167-168`). On login, the client reads it and uses it
(`src/client/authClient.ts:228`: `const iterations = pbkdf2Iterations ?? 100_000`).

**Impact.** An email account whose server-pinned iteration count is set absurdly low loses essentially
all offline brute-force resistance against a stolen ciphertext (the entire point of PBKDF2). Because
the count is **per-user and returned to any caller of `/challenge` for that email**
(`src/server/routes.ts:167-168`), an attacker who exfiltrates the server DB (or simply probes `/challenge`)
sees the count and targets the weakest accounts. This directly undermines the threat model's T3
("PBKDF2 @ 600k default") for any account an attacker can *create* with a low count. A pathological
value (`1e15`) is also a server-side CPU-DoS vector on `/login`, since the client does the PBKDF2 —
but a client could also just lie about having done it; the server cost is bounded, so the
brute-force-weakening direction is the serious one.

**Recommendation.** Enforce a server-side floor at registration (and a sane ceiling):

```ts
// In register(), after reading body:
function validateIterations(n: unknown): number | null {
  if (typeof n !== "number" || !Number.isInteger(n) || !Number.isFinite(n)) return null;
  if (n < 100_000 || n > 1_000_000) return null; // floor = OWASP-min / legacy; cap = level-3
  return n;
}
if (body.authMethod !== "wallet" && body.pbkdf2Iterations != null) {
  const ok = validateIterations(body.pbkdf2Iterations);
  if (!ok) return error("Invalid pbkdf2Iterations", 400);
}
```

Use the **minimum** of the documented `PBKDF2_ITERATIONS` levels (`100_000`) as the floor so legacy
level-1 accounts still register, but nothing weaker can ever be pinned. Add a test asserting
`pbkdf2Iterations: 1` is rejected with 400.

---

### F4 — MEDIUM: `import-wallet` appends attacker-controlled ciphertext without ownership binding

**Location:** `src/server/routes.ts:392-408` (`importWallet`), `src/server/routes.ts:115-130` (`validateWallets`).
**Severity:** Medium.

**Problem.** `importWallet` requires a **valid session** (good — `verifySession` at
`src/server/routes.ts:395`) but then appends any `body.wallets[]` the caller supplies to the user's
record and persists them (`src/server/routes.ts:405-406`). The wallet entries are validated for shape
only (`validateWallets`, `src/server/routes.ts:115-130`): each needs a `publicKey`, an
`encryptedSecret`, a non-empty `role`, and a `chain` ∈ {solana, evm}. There is **no check that the
caller can decrypt the ciphertext** (i.e. that it was encrypted under the account's app key) and **no
uniqueness/dedup on `publicKey`** — an attacker with a stolen session can append arbitrary
ciphertext blobs up to `maxWalletsPerUser` (64).

```ts
// src/server/routes.ts:405-406
user.wallets = [...user.wallets, ...body.wallets];
await persistUser(storage, user, config);
```

**Impact.**
- **Record poisoning / DoS:** A stolen or XSS-captured session token can push up to 64 garbage wallet
  entries onto the victim's record (filling it to the cap), after which the victim can no longer
  import legitimate wallets. The cap exists as a bloat guard but doubles as a cheap per-user DoS
  amplifier for a token thief.
- **Deception / supply-chain confusion:** An attacker can register a wallet entry whose `publicKey`
  is the victim's *own* funds key but whose `encryptedSecret` is garbage; the client UI may then
  surface a "wallet" that can never be decrypted, or — depending on integrator code that matches on
  `publicKey` — shadow the real entry.
- **Note (not a vuln):** because decrypt fails closed (GCM tag), poisoned entries cannot leak funds
  by themselves. The risk is integrity/availability, not direct key compromise.

**Recommendation.**
- Require the caller to **prove the imported secret decrypts under the account's app key** before
  persisting: since the server holds no app key, require the client to also present a freshly signed
  challenge (derived auth key) as a re-auth ceremony on `import-wallet`, *or* accept imports only via
  the existing `withDecryptedKey` round-trip on the client and have the client re-encrypt under the
  app key (which it already does for `generateWalletBundle`). The cheapest hardening is to **reject
  duplicate `publicKey` within the record** so an entry can't shadow another.
- Apply `validateWallets`'s per-batch 16-cap *and* dedup against existing `user.wallets` by `publicKey`.

---

### F5 — LOW: AES-GCM key is imported as extractable raw bytes; no AAD / context binding

**Location:** `src/core/crypto.ts:64-93` (`importAesGcmKey`, `encryptSecret`/`decryptSecret`).
**Severity:** Low.

**Problem.** The wallet-secret encryption imports the app key as a raw AES-GCM `CryptoKey` with
`extractable: false` *on the CryptoKey object* (`src/core/crypto.ts:65`), but the **input bytes**
(`appKeyToBytes(appKey)`, `src/core/crypto.ts:43-48`) are a JS `Uint8Array` derived from the hex app key
that already lives in memory as a string. The "non-extractable" property therefore protects nothing
here — the secret is the hex string, not the `CryptoKey`. Additionally, GCM is called with **no
`additionalData` / AAD** (`src/core/crypto.ts:76,88`), so the ciphertext is not context-bound to
(chain, role, publicKey, owner). A ciphertext moved between two wallet entries of the same account
decrypts interchangeably.

**Impact.** Low. The app key is memory-only and the real protection is the auto-locking vault. But:
- A Solana and an EVM secret encrypted under the same app key have **identical structure** — swapping
  an `encryptedSecret` between two entries of the same user yields a "valid" decryption that produces
  the wrong-type key (a 64-byte Solana secret fed to `Keypair.fromSecretKey`, or a 0x EVM key). This
  is a robustness/confusion hazard, not a key leak.
- Lack of AAD means the ciphertext carries no integrity statement about *what* it is.

**Recommendation.**
- Bind context with AAD: `additionalData: utf8(\`${appId}:${publicKey}:${chain}:${role}\`)` in both
  `encryptSecret` and `decryptSecret`. This makes a transplanted ciphertext fail the GCM tag check.
  (Wire format stays `iv:ct+tag`; the AAD is derived from the entry, not stored.)
- Document honestly that `extractable: false` is best-effort given the hex-string key already in
  memory; the memory-only vault is the actual control (already stated in CRYPTO_SPEC §8).

---

### F6 — LOW: `pbkdf2Iterations` fallback (100k) silently weakens legacy/missing accounts on login

**Location:** `src/client/authClient.ts:117` (re-auth) and `src/client/authClient.ts:228` (login):
`const iterations = pbkdf2Iterations ?? 100_000;`
**Severity:** Low.

**Problem.** When the server returns no pinned count (legacy accounts, or a record where it was never
set), the client **silently falls back to 100k** rather than the configured `securityLevel`. This is
documented as a legacy-compat path, but it means a misconfigured or migrated record quietly runs at
level-1 strength regardless of the deployment's `securityLevel: 2/3`.

**Impact.** Low — affects only accounts without a pinned count, and 100k still decrypts correctly.
The risk is a quiet downgrade invisible to operators.

**Recommendation.** At minimum, `console.warn` when the fallback fires (like the `appId` warning at
`src/client/authClient.ts:96-102`). Ideally, refuse to fall back below the deployment's
`securityLevel` unless an explicit "legacy" flag is set, so the downgrade is intentional and logged.

---

### F7 — LOW: Rate-limit `incr` + `expire` is not atomic on KV backends

**Location:** `src/server/rateLimit.ts:14-36`, `src/storage/kv.ts:36-46`, `src/storage/redis.ts:33-43`.
**Severity:** Low.

**Problem.** `checkRateLimit` does `incr` then, conditionally, a separate `expire`
(`src/server/rateLimit.ts:21-31`). On Redis/KV these are two round trips with no pipeline/MULTI. The
code self-heals a "wedged counter with no TTL" by re-applying `expire` once `count > maxAttempts`
(`src/server/rateLimit.ts:26-31`), which is a thoughtful fix — but there remains a window: if the
process crashes **between** the first `incr` (count becomes 1) and its `expire`, the key lives with
no TTL and blocks that identifier until it next exceeds `maxAttempts` and re-heals. On Upstash/Vercel
KV REST, the two calls are independent HTTP requests, widening that window.

**Impact.** Low. The self-heal at `count > maxAttempts` bounds the lockout; the worst case is a
temporary over-count on one identifier. It is **not** a bypass — an attacker can't exploit it to evade
limiting, only to slightly over-throttle a target.

**Recommendation.** Use an atomic primitive:
- Redis: `SET key 0 EX window NX` to seed, then `INCR`; or a Lua script that does incr+expire
  atomically. ioredis supports `eval`.
- Upstash/KV: use the `EX` option on the first `INCR` is not available; instead seed with
  `SET ... NX EX` before the first `INCR`, or accept the documented self-heal and note it.

Lower priority than F1–F4.

---

### F8 — LOW: `timingSafeEqual` reads out-of-bounds on length mismatch

**Location:** `src/core/crypto.ts:134-141`.
**Severity:** Low (robustness/defensive-depth; no security bypass observed).

**Problem.** The constant-time compare loops to `Math.max(a.length, b.length)` and indexes both
strings with `charCodeAt(i)`. On a length mismatch, the shorter string is indexed past its end, so
`charCodeAt` returns `NaN`; `NaN ^ x` → `NaN`; `diff |= NaN` → `diff` becomes `NaN`; `NaN === 0` is
`false`, so the function still returns the correct answer (`false`). I **runtime-verified** it does
not false-accept (all six probe cases below returned `false`). So this is **not** a security bug today.

```text
node /tmp/verify_tse.cjs
equal same-length: true
shorter vs longer: false
identical prefix len differs: false
empty vs abc: false
prefix-equal len mismatch (no false-accept): false
32-byte session vs empty: ...: false
```

However, relying on `NaN`-propagation for correctness is fragile (a future edit that, e.g., does
`diff = diff | 0` per-iteration or guards the XOR differently could silently break it), and the OOB
read is itself a code-smell. The test suite at `tests/timing-safe-edge-cases.test.ts:24-32` explicitly
relies on the "runs full max length" behavior, which is what causes the OOB.

**Recommendation.** Pad-independent, no-OOB constant-time compare:

```ts
export function timingSafeEqual(a: string, b: string): boolean {
  // Compare over a fixed window with the length baked into diff; no OOB read.
  const la = a.length, lb = b.length;
  const len = Math.max(la, lb);
  let diff = la ^ lb; // non-zero on length mismatch
  for (let i = 0; i < len; i++) {
    const ca = i < la ? a.charCodeAt(i) : 0;
    const cb = i < lb ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}
```

This preserves the constant-time-over-max-length property the tests assert while removing the OOB.

---

### F9 — LOW: Biometric registration descriptor persisted in `localStorage` survives logout

**Location:** `src/react/useBiometricUnlock.ts:18-39, 104-113` (`ttc_biometric_reg`), vs.
`src/client/biometricUnlock.ts:225-234` + `src/client/session.ts:305-323` (the purge hook).
**Severity:** Low.

**Problem.** The React hook persists the (non-secret) `PasskeyRegistration` descriptor under
`localStorage["ttc_biometric_reg"]` so `unlock()`/`disable()` can be argless
(`src/react/useBiometricUnlock.ts:33-35`). On logout, the client layer's `clearSession` hook purges the
`ttc_biometric_unlock` marker + IndexedDB blob/gate secret (`src/client/biometricUnlock.ts:225-234`),
but **nothing clears `ttc_biometric_reg`** — it lives in the React layer's own key, not hooked into
`registerSessionClearHook`. So after logout, `loadReg()` still returns a stale registration and
`hasBiometricUnlock()` (which checks the *client* marker `ttc_biometric_unlock`, purged) returns
`false` — an **inconsistent state**: `isEnabled=false` but `ttc_biometric_reg` is still on disk.

**Impact.** Low. The registration is non-secret (`{ credentialId, salt, rpId, mode }`), and the
secret-bearing blob it points to *is* purged, so a subsequent `unlock()` fails closed
(`unwrapAppKey` throws "No biometric-unlock blob"). The hazard is a stale, misleading local artifact
and a UI that can show inconsistent enable state; on a shared device it also leaks the credentialId of
a logged-out user.

**Recommendation.** Register a `clearSession` hook (or call `clearReg()` from the hook's effect on
status→unauthenticated) so `ttc_biometric_reg` is purged alongside the client marker on logout.

---

### F10 — INFORMATIONAL: No nonce/IV uniqueness tracking; relies on 96-bit random IV collision improbability

**Location:** `src/core/crypto.ts:72-78` (12-byte random IV per encryption), `src/client/biometricUnlock.ts:83-91`,
`src/client/webauthn.ts:202-219`.

AES-GCM with a **random** 96-bit IV is safe up to the birthday bound (~2^32 encryptions under one key —
NIST SP 800-38D). Per-account wallet counts are tiny (`maxWalletsPerUser: 64`), so this is not an
operational risk. Noted only because the code does not *track* IV reuse and the design doc doesn't
state the limit; a future feature that re-encrypts under one key at high frequency could approach it.

**Recommendation.** Document the ~2^32 ceiling in `CRYPTO_SPEC.md` §3; no code change needed for the
current usage.

---

### F11 — INFORMATIONAL: `verifySolanaSignature` does not pin a canonical message format / no replay domain separation across appId

**Location:** `src/server/signature.ts:24-37`, `src/core/index.ts:8-10`.

`walletLoginMessage(challenge)` is `"Sign this message to verify wallet ownership: ${challenge}"` — it
does **not** include `appId`, `origin`, or an expiry. The single-use atomic challenge is the replay
defense (and it's a good one), so this is fine **as long as** the challenge is always consumed
atomically. It is (`challenge.ts:25-35`). Noted only because the message is not domain-separated from
`walletAppKeyMessage` (the key-derivation message, which *does* carry `appId`) — if a future refactor
ever made the login message deterministic, it could collide with the app-key message semantics. Keep
the two messages visually/structurally distinct (they are).

**Recommendation.** No change; document the invariant that the login message must stay
challenge-dependent and structurally distinct from the app-key message.

---

## 3. Aggregated hardening roadmap

| Priority | Finding | Action | Breaking? |
|---|---|---|---|
| **P0** | F1 (biometric not hardware-bound) | Server-side WebAuthn assertion verify (attestation at register, `origin`/`rpIdHash`/`signCount`/UV at login) via `@simplewebauthn/server`. Extends `UserData` with credential fields. | Yes (biometric accounts re-register) |
| **P0** | F3 (no PBKDF2 floor) | Validate `pbkdf2Iterations` server-side: integer, 100k–1M. Reject otherwise. | No |
| **P1** | F2 (no proof-of-control on register) | Require email/biometric register to sign+consume the single-use challenge; tighten `validatePublicKey` per `authMethod`. | Minor (client) |
| **P1** | F4 (import-wallet poisoning) | Re-auth ceremony on import; dedup `publicKey` within record. | Minor (client) |
| **P2** | F5 (no AAD) | Bind ciphertext to `(appId, publicKey, chain, role)` via GCM AAD. | Yes (ciphertext re-encrypt / re-register) |
| **P2** | F8 (timingSafeEqual OOB) | Replace with the bounds-checked variant above. | No |
| **P2** | F9 (stale biometric reg) | Purge `ttc_biometric_reg` on logout. | No |
| **P3** | F6 (silent 100k fallback) | Warn / refuse below `securityLevel`. | No |
| **P3** | F7 (non-atomic rate-limit) | Atomic incr+expire (Redis Lua / KV NX seed). | No |
| **P3** | F10, F11 | Documentation only. | No |

**Suggested sequencing for a Turnkey-replacement release:** F3 + F8 + F9 are non-breaking and should
land immediately. F1 + F2 + F4 + F5 form one breaking release (re-register for affected accounts),
consistent with the maintainer's no-migration policy and the WI-15/WI-16 plan in
[`audits/v0.3.2-PRD.md`](./v0.3.2-PRD.md). F7/F6/F10/F11 can follow.

---

## 4. Patched code

### 4.1 `src/core/crypto.ts` — bounds-checked `timingSafeEqual` (F8)

```ts
/**
 * Constant-time comparison of two hex strings. Compares over a fixed
 * max-length window with the length baked into `diff`, so it never indexes
 * either string out of bounds and still returns false on any mismatch
 * (including length). Pure, no Node 'crypto' needed.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const la = a.length;
  const lb = b.length;
  const len = Math.max(la, lb);
  let diff = la ^ lb; // non-zero iff lengths differ — folded in up front
  for (let i = 0; i < len; i++) {
    const ca = i < la ? a.charCodeAt(i) : 0;
    const cb = i < lb ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}
```

The existing `tests/timing-safe-edge-cases.test.ts` suite continues to pass (it asserts
"runs full max length" and "length mismatch returns false"), and the OOB is gone.

### 4.2 `src/server/routes.ts` — PBKDF2 floor + register proof-of-control + import dedup (F2/F3/F4)

```ts
// Near the top, with the other validators:
const PBKDF2_MIN = 100_000;
const PBKDF2_MAX = 1_000_000;
function validateIterations(n: unknown): number | null {
  if (typeof n !== "number" || !Number.isInteger(n) || !Number.isFinite(n)) return null;
  if (n < PBKDF2_MIN || n > PBKDF2_MAX) return null;
  return n;
}

// In register(), replace the unconditional pbkdf2Iterations pin:
if (body.authMethod !== "wallet" && body.pbkdf2Iterations != null) {
  const ok = validateIterations(body.pbkdf2Iterations);
  if (!ok) return error("Invalid pbkdf2Iterations", 400);
}

// In register(), for the email/biometric branch (authMethod !== "wallet"),
// require and consume a single-use challenge signed by the derived auth key:
} else {
  if (!body.authPublicKey) return error("authPublicKey required for email/biometric registration");
  if (!body.signature || !body.challenge) return error("signature and challenge required");
  // Challenge is single-use and scoped to THIS publicKey; derive the expected
  // publicKey from body, but the auth signature must verify against authPublicKey.
  if (!verifyAuthSignature(body.authPublicKey, body.signature, body.challenge)) {
    return error("Signature verification failed", 401);
  }
  const ok = await consumeChallenge(storage, body.publicKey, body.challenge, config);
  if (!ok) return error("Invalid or expired challenge", 401);
}

// In importWallet(), dedup by publicKey so an attacker can't shadow an entry:
const existing = new Set(user.wallets.map((w) => w.publicKey));
const incoming = body.wallets.filter((w) => !existing.has(w.publicKey));
if (!incoming.length) return error("no new wallets to import", 400);
if (user.wallets.length + incoming.length > config.maxWalletsPerUser) {
  return error("wallet limit reached", 400);
}
user.wallets = [...user.wallets, ...incoming];
```

> Note: making email/biometric register consume a challenge is a **client-side breaking change** —
> `registerWithEmail`/`registerWithBiometric` must first fetch a challenge and sign it. The
> `walletHandshake` pattern in `authClient.ts:251-264` is the template. This aligns register with the
> existing login/loginWallet/connectWallet ceremony and closes F2.

### 4.3 `src/core/crypto.ts` — AAD-bound GCM (F5)

```ts
// Thread an optional context string through:
export async function encryptSecret(
  plaintext: string,
  appKey: string,
  aad?: string,
): Promise<string> {
  const key = await importAesGcmKey(appKey, ["encrypt"]);
  const iv = new Uint8Array(new ArrayBuffer(12));
  crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad ? new TextEncoder().encode(aad) : undefined },
    key,
    new TextEncoder().encode(plaintext),
  );
  return `${b64urlEncode(iv)}:${b64urlEncode(new Uint8Array(ct))}`;
}

export async function decryptSecret(
  ciphertext: string,
  appKey: string,
  aad?: string,
): Promise<string> {
  const parts = ciphertext.split(":");
  if (parts.length !== 2) throw new Error("Decryption failed: malformed ciphertext");
  const key = await importAesGcmKey(appKey, ["decrypt"]);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64urlDecode(parts[0]!), additionalData: aad ? new TextEncoder().encode(aad) : undefined },
      key,
      b64urlDecode(parts[1]!),
    );
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  }
}
```

Callers in `src/client/wallet.ts` pass `aad = \`${appId}:${publicKey}:${chain}:${role}\``. This is a
ciphertext-format change → re-register for affected accounts.

---

## 5. Testing recommendations (new cases to add)

| # | Test | Expected (post-fix) |
|---|---|---|
| T1 | `register` email with `pbkdf2Iterations: 1` | 400 (F3) |
| T2 | `register` email with `pbkdf2Iterations: NaN` / `1e9` / `"600000"` | 400 (F3) |
| T3 | `register` email/biometric **without** signature+challenge | 400 (F2) |
| T4 | `register` email with a `publicKey` already squatted by an email account, then victim `connectWallet` | victim still recovers (F2 mitigation) |
| T5 | `importWallet` with a `publicKey` already in the record | 400 / deduped (F4) |
| T6 | `importWallet` pushing past `maxWalletsPerUser` with duplicate keys | capped, no shadow (F4) |
| T7 | Biometric login with a software-derived key on a **lookalike rpId** | rejected server-side (F1, post WI-15) |
| T8 | Replayed WebAuthn assertion (`signCount` not increasing) | rejected (F1) |
| T9 | GCM decrypt with a ciphertext whose entry context differs (swapped chain/role) | throws (F5) |
| T10 | `timingSafeEqual("a","abc")` and all length-mismatch probes | false, no `NaN` reliance (F8) — already green |
| T11 | Logout clears `localStorage["ttc_biometric_reg"]` | key absent after `clearSession()` (F9) |

The existing `tests/audit-server.test.ts:104-116` currently **asserts the insecure F2 behavior**
(registers an arbitrary `publicKey` with no proof of control → 201). When F2 is fixed, that test must
flip to assert 400, exactly as `dual-bundle-vault.test.ts` flipped for the vault-singleton fix (per
the contributing guide in `README.md`).

---

## 6. Additional / release-engineering recommendations

1. **`npm publish --provenance`** (SLSA) from CI and **`osv-scanner` + `npm audit --omit=dev`** gate —
   carried from [`audits/v0.3.2-PRD.md`](./v0.3.2-PRD.md) §3, still open. The single runtime dep
   `@noble/hashes@2.2.0` is a good supply-chain posture; provenance closes the trust loop.
2. **`CHANGELOG.md`** explicitly listing the **breaking** defaults already in effect (memory-only vault,
   signature auth/no `passkeyHash`, AES-GCM, 600k PBKDF2, 4h TTL, `crypto-es` removed) plus the
   F1/F2/F5 breaks — so integrators adopting this *as a Turnkey replacement* know exactly what
   changes derived keys.
3. **Threat-model wording:** re-classify **WI-15 (F1) as Critical for the wallet-as-a-service use
   case** in `docs/THREAT_MODEL.md` §4 (R6) — it is currently listed as a generic residual. The
   README's claim that biometric uses "`userVerification: required`; PRF preferred" is accurate for
   the *client* but the server makes no such check; the docs should state this asymmetry plainly.
4. **Integrator obligations (THREAT_MODEL §5) should be promoted to *required* for a custody
   replacement:** strict CSP + Trusted Types + SRI, email verification + CAPTCHA before register, and
   edge rate limiting are not optional when this SDK is the wallet layer. Consider gating
   `register`/`connect-wallet` behind an integrator-provided verification token in the SDK contract.
5. **`dist/` is checked in** (root `dist/` present at audit time). Publishing from CI from a clean
   build is safer than committing build artifacts; at minimum add `dist/` provenance to the release
   notes.
6. **`.git-blame-ignore-revs` exists** (good) — keep it updated as formatting/refactor commits land.

---

## 7. What this audit did NOT find (positive confirmation)

For completeness, these commonly-exploited classes were checked and are **correctly handled** in
v0.3.2 — they are *not* findings:

- **Unauthenticated / malleable encryption** — AES-256-GCM, tag verified on decrypt, generic error
  (`src/core/crypto.ts:72-93`). No CBC, no unauthenticated path. (`tests/ciphertext-tampering.test.ts`
  green.)
- **`crypto-es` / weak RNG** — removed; `randomHex` throws if `getRandomValues` missing, no
  `Math.random` fallback (`src/core/crypto.ts:96-106`). Single runtime dep `@noble/hashes`.
- **PBKDF2 strength** — 600k default, per-user pinned, `appId`-domain-separated salt
  (`src/core/config.ts:44-48`, `src/core/crypto.ts:23-33`). (The *floor* is the issue — see F3.)
- **Server-stored passkey secret** — none; auth is ed25519 signature vs. stored public key
  (`src/server/signature.ts:45-58`).
- **Challenge replay** — 256-bit, atomic `getdel`, single-use, TTL-bound, constant-time compare
  (`src/server/challenge.ts:25-35`).
- **Session token weakness** — 256-bit CSPRNG, 4h TTL, single-active-session (login revokes prior),
  optional UA binding (`src/server/session.ts`, `src/server/routes.ts:90-99`).
- **Spoofable `X-Forwarded-For` rate-limit bypass** — `trustProxyHeaders` defaults **false**;
  `clientIp` returns `"unknown"` when untrusted (`src/server/http.ts:25-37`). Per-target buckets avoid
  global lockout (`src/server/routes.ts:73-88`).
- **Storage key-namespace collision** — `session:` and `pubKey:` prefixes are disjoint by construction
  (`src/core/config.ts:3-15`); `getUserByPublicKey` guards `JSON.parse` (`src/server/session.ts:39-44`).
- **Memory-only app key** — never in `sessionStorage`/`localStorage`; auto-lock idle/hide/freeze/bfcache
  + cross-tab lock signal; shared via `Symbol.for` across bundles (`src/client/session.ts`).
- **Reveal extending the signing window** — `revealSecret` derives a one-time key and does not arm the
  session (`src/client/authClient.ts:161-168`).
- **Per-op key lifetime** — `withDecryptedKey` drops the plaintext reference after signing
  (`src/client/wallet.ts:100-111`); Solana/EVM signers `fill(0)` the keypair after use
  (`src/react/useSolanaSigner.ts:53,64,73`).
- **EVM as an auth identity** — intentionally none; external wallet login is Solana-only
  (`src/server/signature.ts` has no EVM verifier). EVM keys are internal signing wallets. (By design;
  `tests/evm-verification.test.ts`, `tests/audit-server.test.ts:84-100`.)

---

## 8. Verdict

As an **embedded-wallet + auth library**, `@tetrac/login-sdk` v0.3.2 has a **sound, modern
cryptographic core** and is materially better than what the prior generic audits assumed. As a
**drop-in replacement for Privy / Turnkey Wallet-as-a-Service**, it is **not yet production-defensible**:
the biometric login is not bound to a hardware assertion (F1, Critical for this use case), the server
imposes no KDF floor (F3, High), and registration accepts attacker-chosen identities with no
proof-of-control (F2, High). Close **F1 + F3 + F2 + F4** (one breaking release, per the existing
WI-15 plan) and the SDK's trust model becomes coherent with its custody-replacement ambition. The
remaining items (F5–F11) are hardening and documentation.

Full test suite (25 suites / 179 tests) is green at audit time. Findings F8 and the rate-limit
atomicity (F7) were runtime-verified; F8 confirmed not to false-accept.
