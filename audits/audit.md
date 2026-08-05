# Security Audit — `@tetrac/login-sdk` v0.6.0

|                     |                                                                                                                                                                                                                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Package**         | `@tetrac/login-sdk`                                                                                                                                                                                                                                                                      |
| **Version**         | 0.6.0                                                                                                                                                                                                                                                                                    |
| **Commit / branch** | `6311e29` on `v0.5.1`                                                                                                                                                                                                                                                                    |
| **Date**            | 2026-08-05                                                                                                                                                                                                                                                                               |
| **Scope**           | Full `src/` tree (8,523 LoC) — core crypto, server routes, session/challenge/rate-limit, storage (KV + SQL), browser client + vault, WebAuthn, React hooks, UI, Ledger                                                                                                                   |
| **Out of scope**    | `dist/` build output, consumer applications, the demo app, infrastructure/hosting                                                                                                                                                                                                        |
| **Method**          | Manual source review of every file in `src/`, plus an executable proof-of-concept harness run against the real route handlers and storage layer. Every finding below marked _Confirmed_ was reproduced; findings marked _By inspection_ are reasoned from code and are labelled as such. |

## Verdict

The cryptographic core is sound, and the storage layer is unusually well-defended — the hazards that normally sink a bring-your-own-database auth SDK (expiry-on-read, atomic challenge consume, permanent rate-limit lockout, MySQL collation collapse, world-readable Supabase `public` schema) are each solved once, centrally, and regression-tested.

The defects are **not in the crypto**. They are in **record lifecycle and abuse resistance**: the server does read-modify-write on the user record with no concurrency control, which silently and permanently destroys non-custodial wallet keys; and the anti-abuse controls are keyed on attacker-chosen identifiers, so they neither bound resource consumption nor prevent targeted denial of a named account.

**2 High, 4 Medium, 5 Low. No Critical.** H-1 should block a production release.

### Baseline state

- `npm run typecheck` — clean.
- `npx jest` — **43 suites / 459 tests pass**, 3 suites (12 tests) skipped (Postgres/MySQL/Redis conformance; require `npm run docker:up`).
- Runtime dependency closure is a single package: `@noble/hashes@2.2.0`.

---

## Findings

| ID  | Severity | Title                                                                | Status        |
| --- | -------- | -------------------------------------------------------------------- | ------------- |
| H-1 | **High** | Lost update on `UserData` silently destroys encrypted wallet keys    | Confirmed     |
| H-2 | **High** | Unauthenticated, unbounded record creation and payload size          | Confirmed     |
| M-1 | Medium   | Targeted account lockout via the per-target challenge bucket         | Confirmed     |
| M-2 | Medium   | Account squatting — no ownership proof binds an email to an account  | Confirmed     |
| M-3 | Medium   | Gate-mode biometric secret is recoverable by any same-origin script  | By inspection |
| M-4 | Medium   | Ledger app-key derivation is pinned to a firmware-dependent envelope | By inspection |
| L-1 | Low      | Route dispatch resolves `Object.prototype` members                   | Confirmed     |
| L-2 | Low      | Client `authHeaders()` ignores configured header names               | By inspection |
| L-3 | Low      | Horizontal enumeration is unthrottled under the default config       | Confirmed     |
| L-4 | Low      | No `Cache-Control: no-store` on authenticated responses              | By inspection |
| L-5 | Low      | "Single active session" is not enforced under concurrency            | By inspection |

---

### H-1 — Lost update on `UserData` silently destroys encrypted wallet keys

**Severity: High** · **Status: Confirmed** · `src/server/routes.ts:523-540`, `src/server/session.ts:12-14,40-72`, `src/storage/store.ts:200-205`, `src/storage/sql/engine.ts:93-114`

Every write path is a read-modify-write of the whole `UserData` blob with no optimistic concurrency:

1. `verifySession()` / `getUser()` loads a snapshot,
2. the handler mutates it in memory,
3. `persistUser()` upserts the **entire record**, overwriting whatever is there.

`putUser` is a full-blob upsert on every backend — `SET` on KV, `INSERT … ON CONFLICT DO UPDATE SET data = ?` on SQL. There is no version column, no CAS, no `WATCH`. Two overlapping requests for the same account each write their own stale snapshot, and the later write wins wholesale.

The blast radius is widened by `issueSession()`, which calls `persistUser()` on **every login** solely to record `authTokenHash` — so an ordinary login is a full-record overwrite that races anything else touching that account.

**Reproduced:**

```
concurrent import-wallet + login  →  wallets after: ["ct0"]              (imported wallet GONE)
two concurrent import-wallet      →  wallets after: ["ct-B"]             (ct-A GONE)
```

**Impact.** `encryptedSecret` is the _only_ copy of a client-generated private key — the plaintext existed in the browser for the duration of `generateWalletBundle()` and was never persisted anywhere else. Losing that ciphertext is unrecoverable by design: no backup, no escrow, no re-derivation. Any assets already sent to that address are permanently stranded. The failure is silent — both requests return `200`, and the user only discovers it later when a wallet has vanished from `useWallets()`.

Realistic triggers: two tabs, a retried request, an import that overlaps a background re-login, or any client that fires `refetchUser()` alongside a mutation.

**Remediation** (in order of preference):

1. Add a monotonic `version` to `UserData` and make the port `putUser(user, expectedVersion)`, rejecting on mismatch. SQL gets it nearly free — `UPDATE … SET data = ?, version = version + 1 WHERE version = ?` inside the existing transaction; KV needs `WATCH`/`MULTI` or a small Lua script. Callers retry the read-modify-write on conflict.
2. Independently, stop rewriting the whole record just to store a session pointer: give `AuthStore` a narrow `setSessionPointer(appId, publicKey, tokenHash)` so login stops colliding with wallet writes.
3. Make wallet append an explicit store operation (`appendWallets(appId, publicKey, wallets, max)`) executed server-side/transactionally, rather than an array concat in the handler.

Add a conformance case for it — the current suite covers the email index's no-lost-write property but not the user record's.

---

### H-2 — Unauthenticated, unbounded record creation and payload size

**Severity: High** · **Status: Confirmed** · `src/server/routes.ts:182-197,241-334,426-484`

Three gaps compound on the anonymous `POST /register` and `POST /connect-wallet` paths.

**(a) `validateWallets()` bounds some fields and not others, and strips nothing.** `publicKey` ≤ 128, `encryptedSecret` ≤ 8192, `chain` is an enum — but `role` is only checked non-empty with **no length cap**, and unknown properties are never removed. The array is stored verbatim: `wallets: body.wallets ?? []` → `JSON.stringify(user)`.

**(b) The rate-limit bucket is keyed on an attacker-chosen identifier.** `{ endpoint: "register", appId, identifier: body.email ?? body.publicKey }`. A fresh `Keypair.generate()` per request is a fresh bucket, so the 10-per-60s limit never fires. The client-IP bucket is skipped entirely because `trustProxyHeaders` defaults to `false`.

**(c) `allowedAppIds` is optional.** Left unset (the default), any well-formed `appId` is accepted, so namespaces are minted at will.

**Reproduced:**

```
one anonymous POST /register       →  6.53 MB persisted under a single user record
40 anonymous POST /register        →  40/40 accepted (limit is 10/60s — never reached)
4 arbitrary appIds                 →  4/4 namespaces created
```

**Impact.** Unauthenticated storage and cost exhaustion against any deployment on the default configuration: Upstash/Vercel KV bill per command and per GB; Redis is memory-resident and will evict or OOM. On MySQL a sufficiently large blob exceeds `MEDIUMTEXT` (16 MB) and errors, which at least fails loudly. There is no cleanup path — these records have no TTL.

**Remediation:**

- Normalize wallet entries to an allowlist before persisting (`{chain, role, publicKey, encryptedSecret}` only) and cap `role` (≤ 64 chars is generous).
- Bound the total serialized record (e.g. reject > 256 KB) and the request body itself in the framework layer.
- Add an abuse bucket that is **not** keyed on caller-supplied identity: per-IP unconditionally where an IP is available, plus a global per-`appId` registration bucket.
- Treat `allowedAppIds` as required in production — warn on boot when it is unset, mirroring the existing default-`appId` warning in `AuthClient`.

---

### M-1 — Targeted account lockout via the per-target challenge bucket

**Severity: Medium** · **Status: Confirmed** · `src/server/routes.ts:202-239`, `src/server/challenge.ts:7-16`

Two mechanisms combine, both reachable with no credentials:

1. `putChallenge` stores **one** challenge per `(appId, publicKey)`, overwriting silently. Anyone who can name the account (an email, or a public key) overwrites a victim's in-flight challenge, so the challenge the victim is currently signing no longer matches.
2. The `/challenge` rate-limit bucket is keyed on the **target** identifier, and every request counts — successes included. Ten anonymous requests exhaust the victim's own bucket.

**Reproduced:**

```
attacker requests a challenge for the victim's email  →  victim's login: 401
10 anonymous /challenge for the victim's email        →  victim's /challenge: 429
```

At 10 requests per minute, one unauthenticated client holds a named account out of its own login indefinitely.

The source comments acknowledge this ("the residual per-target DoS is the developer's edge to own"). The trade-off is real and the reasoning behind per-target keying is right — it avoids the global `"unknown"` lockout. But the accepted cost is understated: this is a complete, sustained, targeted authentication denial, not a throttle.

**Remediation:**

- Store challenges keyed by challenge value under a small per-account set (allow N concurrent, cap N, expire each) so issuing a new one cannot invalidate one already in flight.
- Separate issuance from failure: charge the `/challenge` bucket on the _requester_ where an IP is available, and reserve target-keyed counters for _failed_ verification (as `/login` already correctly does).

---

### M-2 — Account squatting: no ownership proof binds an email to an account

**Severity: Medium** · **Status: Confirmed** · `src/server/routes.ts:241-334`

`register` accepts any well-formed `email` with no verification of any kind, and enforces per-app uniqueness. The first caller to claim an address owns it.

**Reproduced:**

```
attacker registers ceo@company.com   →  201
real user registers ceo@company.com  →  409 Account already exists
real user falls back to login        →  401 Invalid credentials
```

The client's documented "auto" mode (try register, fall back to login on 409) is precisely the path that dead-ends here. The SDK has no recovery mechanism — no `authPublicKey` rotation, no ownership challenge — so the address is permanently unusable on that deployment.

Enumeration (L-3) makes target selection easy, and H-2 makes bulk pre-registration free.

**Remediation.** This is arguably a scope boundary rather than a bug, but it is currently undocumented, which makes it a trap. Either:

- state plainly in the README/SECURITY that `email` is an **unverified label**, and that integrators MUST gate `/register` behind their own verification (magic link / OTP) before exposing it; or
- add an optional `verifyEmail?: (email: string, proof: unknown) => Promise<boolean>` hook in `AuthHandlerOptions` that `register` enforces when configured.

---

### M-3 — Gate-mode biometric secret is recoverable by any same-origin script

**Severity: Medium** · **Status: By inspection** · `src/client/webauthn.ts:200-247`, `src/client/biometricUnlock.ts:59-109`

When the authenticator lacks PRF support, `registerPasskey` falls back to **gate mode**: a random 32-byte secret encrypted under a freshly generated, non-extractable `AES-GCM` `CryptoKey`, with `{cryptoKey, iv, ciphertext}` stored in IndexedDB.

Non-extractability protects the _key bytes_. It does not protect the _decryption capability_. `CryptoKey` is structured-clonable and round-trips through IndexedDB with its `["encrypt","decrypt"]` usages intact, so any script on the origin can open `ttc_passkey_store`, read the record, and call `crypto.subtle.decrypt({name:"AES-GCM", iv}, record.cryptoKey, record.ciphertext)` — recovering the plaintext secret **without any WebAuthn assertion**. The biometric gate is enforced only by control flow in `derivePasskeySecret()`, which an attacker simply does not execute.

Consequences by account type:

- **biometric-PRIMARY** (`registerWithBiometric`): the gate secret _is_ the app key. Recovering it decrypts every wallet — defeating the "app key is memory-only, storage-scraping XSS finds no key at rest" guarantee that the whole vault design rests on.
- **biometric-UNLOCK on any account** (`enableBiometricUnlock`): the gate secret is the HKDF input for the wrap key, and the wrapped blob sits in the same database. Both halves are same-origin readable, so the account's real app key is recoverable.

`tests/biometric-gate-resistance.test.ts` asserts `exportKey` rejects and that GCM catches tampering — both true, and neither is the property that matters here.

PRF mode is unaffected: the PRF output is never persisted and requires a fresh assertion every time.

**Remediation:**

- Require PRF for biometric-PRIMARY registration and for `enableBiometricUnlock`; fail closed with a clear error when `ext.prf.enabled` is false rather than silently downgrading. This is the honest fix — WebAuthn provides no way to make a stored secret genuinely assertion-bound without PRF (ES256 assertion signatures are non-deterministic, so they cannot seed a KDF).
- If gate mode must remain for reach, label it accurately in the docs as a **UX convenience with a weaker at-rest guarantee**, and stop describing gate-mode credentials under the memory-only-key security model.
- Update the test to assert the actual threat: that a same-origin script holding the IndexedDB record cannot recover the plaintext.

---

### M-4 — Ledger app-key derivation is pinned to a firmware-dependent envelope

**Severity: Medium** · **Status: By inspection** · `src/ledger/solanaSigner.ts:82-97`, `src/client/authClient.ts:288-307`, `src/core/crypto.ts:39-41`

For a hardware account the app key is `SHA-256(hex(signature))` over the fixed app-key message. The signature is produced by `createLedgerSolanaSigner.signMessage`, which **cascades** over off-chain envelope layouts — legacy (20-byte header) first, falling back to v0 (85-byte header) only when the device rejects with `0x6a81`.

Which envelope the device accepts is a property of its firmware, and nothing records the choice. If a firmware update changes the accepted layout, the same wallet signing the same message produces a **different signature**, hence a different app key, hence `decryptSecret` fails on every stored wallet.

The server-side verifier correctly accepts either envelope, so _login still succeeds_ — the user authenticates fine and then finds their wallets undecryptable. There is no recovery path.

**Remediation:** pin the envelope at registration — record `offchainEnvelope: "legacy" | "v0"` in `UserData` (it is not secret), return it alongside `pbkdf2Iterations` from `/challenge`, and have the client derive with the pinned layout only, never the cascade. The cascade remains correct for the _auth_ signature, which is challenge-bound and stateless.

---

### L-1 — Route dispatch resolves `Object.prototype` members

**Severity: Low** · **Status: Confirmed** · `src/next/routes.ts:25-48`

`postRoutes` / `getRoutes` are object literals indexed by a URL segment: `const handler = postRoutes[await actionOf(ctx)]`. Inherited properties resolve as truthy.

**Reproduced:**

```
POST /api/auth/constructor  →  handler(req) returns a plain object   (not a Response)
POST /api/auth/toString     →  returns "[object Object]"             (not a Response)
POST /api/auth/valueOf      →  TypeError thrown
POST /api/auth/nope         →  Response 404                          ✓
GET  /api/auth/constructor  →  not a Response
```

Unauthenticated requests produce framework-level 500s and unhandled exceptions instead of a clean 404 — log noise, error-path exercise, and stack exposure in a misconfigured deployment. No route is reachable that shouldn't be.

**Remediation:** build the tables with `Object.create(null)`, or guard with `Object.hasOwn(postRoutes, action)`.

---

### L-2 — Client `authHeaders()` ignores configured header names

**Severity: Low** · **Status: By inspection** · `src/client/session.ts:341-348`

The module-level `authHeaders()` hardcodes `"ttc-auth-token"` and `"ttc-public-key"` while `AuthClient.authHeaders()` correctly reads `config.appIdHeader`. Any deployment that overrides `sessionHeader` or `publicKeyHeader` in `AuthConfig` will have the client send headers the server never reads — every authenticated request 401s. The config options are effectively non-functional.

**Remediation:** thread the resolved config through (or drop the two options from `AuthConfig` if they are not intended to be configurable).

---

### L-3 — Horizontal enumeration is unthrottled under the default config

**Severity: Low** · **Status: Confirmed** · `src/server/routes.ts:202-239,506-521`, `src/server/http.ts:25-37`

`/challenge` returns `200 {challenge}` for a known email and `400 "publicKey or email required"` for an unknown one — a clean account-existence oracle. `/search-wallet` is an explicit one for public keys.

Per-target bucket keying means each probed identifier gets its own counter, so sweeping _N distinct_ addresses is _N_ unthrottled requests. The only global control is the client-IP bucket, and `trustProxyHeaders` defaults to `false` (correctly — trusting `x-forwarded-for` blindly is worse), so on a default deployment nothing bounds a sweep. This is the same root cause as H-2(b), viewed from the privacy side.

**Remediation:** document `trustProxyHeaders: true` + `trustedProxyHops` as a production requirement behind a known proxy; add a global per-`appId` bucket for the enumerable endpoints; and consider returning a well-formed dummy challenge for unknown emails so the response shape carries no signal.

---

### L-4 — No `Cache-Control: no-store` on authenticated responses

**Severity: Low** · **Status: By inspection** · `src/server/http.ts:3-8`

`json()` sets only `content-type`. `GET /user-data` returns the full user record including every encrypted wallet blob, with no cache directives.

Next's static route-handler cache does not apply (the handler reads request headers, which opts it out), and auth is header-based rather than cookie-based, so this is hardening rather than a live bug. But a response with no cache headers is heuristically cacheable, and any shared cache keyed on URL alone would be able to serve one user's record to another.

**Remediation:** add `"cache-control": "no-store"` in `json()`.

---

### L-5 — "Single active session" is not enforced under concurrency

**Severity: Low** · **Status: By inspection** · `src/server/session.ts:40-72`

`issueSession` revokes the previous session by the `authTokenHash` on its snapshot, then writes a new one. Two concurrent logins both read the same previous hash, both delete it, both `putSession`, and only one hash survives in the record. The other session key remains live in storage and is **unrevocable** — the record no longer points at it — until its TTL expires. Same root cause as H-1.

**Remediation:** covered by the H-1 fix (CAS on the user record), or by maintaining a per-user session index rather than a single pointer.

---

## Verified as correct

These were examined specifically and found sound. Recorded so a future audit does not re-litigate them.

**Cryptography**

- Secret encryption is authenticated AES-256-GCM via WebCrypto, fresh 96-bit CSPRNG IV per encryption, auth tag enforced on decrypt, no CBC compatibility path (`core/crypto.ts:72-93`).
- Session tokens are 256-bit CSPRNG values; storage sees only `SHA-256(token)`, both as the session key and as `authTokenHash`. A database read yields no replayable credential. The rationale for a bare hash over a KDF here is correct — the input is uniform 2^256, so stretching would only add per-request latency.
- App keys are domain-separated by `appId` on both paths: PBKDF2 salt = `SHA-256(appId : email)`, and the wallet app-key message embeds `App: {appId}`. A key coerced on one deployment does not unlock the same user on another.
- Auth keypair seed is domain-separated from the encryption key (`SHA-256("ttc-auth-v1:" + appKey)`), so the two are independent.
- `timingSafeEqual` folds the length difference into the accumulator and scans the full max-length window with 0-substitution past the end — no out-of-bounds indexing, no `NaN` reliance, no early exit.
- Biometric-unlock wrapping uses HKDF-SHA-256 → AES-256-GCM; the raw PRF secret is never used directly as a key.
- `generateStrongPasskey` uses `crypto.getRandomValues` only, enforces a 128-bit floor, and its base58 encoder is a full big-integer long division — no modulo bias.

**Protocol**

- Challenge consume is atomic get-and-delete on every backend — `GETDEL` (Redis), `DELETE … RETURNING` (Postgres/SQLite), `SELECT … FOR UPDATE` + `DELETE` in a transaction (MySQL) — with the constant-time comparison in the caller, never in the backend.
- Verify-signature-first, penalize-on-failure ordering on `login` / `login-wallet` / `connect-wallet` / wallet `register`: a forged signature never reaches `consumeChallenge` (so it cannot burn a victim's pending challenge), and a valid login is never throttled by an attacker's failed attempts.
- Sessions are app-scoped, so a token minted by one tenant is never honored by another; the session keyspace is disjoint from the `pubKey:` keyspace, so an attacker-chosen public key cannot collide with a token.
- `appId` is validated against `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` — excluding the `:` namespace separator — _before_ it reaches any storage key; `headerAppId` fails closed to 401 on a malformed value.
- `publicKey` is validated as canonical base58 decoding to exactly 32 bytes, via a `toBase58()` round-trip that rejects left-padded short inputs and EVM `0x…` addresses.
- PBKDF2 iterations are pinned per user and bounds-checked server-side to [100k, 1M], so a malicious client cannot kneecap an account's KDF.
- `publicUser()` strips `authTokenHash` and the legacy raw `authToken` from every response.
- Auth is header-based, not cookie-based — no ambient authority, so the API is not CSRF-exposed.

**Storage**

- The rate limiter fails closed by construction: no `try/catch` in `checkRateLimit`, so a store that cannot count 500s rather than granting permission.
- The permanent-lockout bug class is closed on both ports — the KV path self-heals a TTL-less counter exactly once per window (firing on every over-limit hit would let sustained traffic hold the window open forever), and the SQL path's `CASE WHEN expires_at <= ? THEN 1 ELSE count + 1 END` makes an expired counter start fresh. Both are regression-tested.
- Every SQL read filters `expires_at > ?`; `sweepExpired` is space reclamation only, never the expiry authority.
- All SQL is templated with bound parameters — no string interpolation of user input anywhere. The only interpolated value is a `limit`, sanitized with `Math.max(1, limit | 0)`.
- `putUser` writes the record and the email index in one transaction, with the index keyed `(email, app_id)` — one row per tenant — so concurrent same-email registrations under different `appId`s cannot lose a write.
- MySQL key columns are `VARBINARY` (not `VARCHAR`, not `utf8mb4_bin`), and `mysql2`'s `Buffer` return is decoded in the driver. Preflight refuses to boot on non-strict mode or non-binary key columns.
- Postgres preflight refuses to boot on the `public` schema — the Supabase/PostgREST world-readable-table failure — without an explicit opt-in.
- SQLite preflight refuses a database file under a web-served directory and warns on group/other-readable permissions.
- `resolve.ts` refuses to fall back to `localhost` Redis in production rather than silently giving each instance an ephemeral store.

**Client**

- The app key is memory-only, held on a `Symbol.for()`-keyed global so all bundle copies share one vault; auto-locks on idle, `visibilitychange`, `freeze`, `pagehide`, and bfcache restore; cross-tab lock/logout propagation via the `storage` event.
- `useSigner` reads the app key at **call time**, never captured at render, so a lock racing a render cannot let a stale key decrypt.
- Reveal always runs a fresh ceremony and derives a one-time key — it never reads the ambient session key and never arms the vault.
- No `eval`, `new Function`, `innerHTML`, `dangerouslySetInnerHTML`, or `document.write` anywhere in `src/`. No secret is logged: the only `console` calls are three configuration warnings.

---

## Dependency posture

The SDK's own runtime dependency closure is **one package** — `@noble/hashes@2.2.0` — which is clean. Everything else is an optional `peerDependency` under the consumer's control, or dev-only.

`npm audit` reports 8 advisories (4 high, 3 moderate, 1 low). None are in the SDK's runtime closure:

| Package                                 | Severity          | Path                                           | Assessment                                                                                                                                                                                                             |
| --------------------------------------- | ----------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ws`                                    | high              | `@solana/web3.js` → `jayson`; `viem` → `isows` | DoS in the WebSocket RPC client. The SDK never opens an RPC connection — it uses `@solana/web3.js` only for `PublicKey`/`Keypair` and `viem` only for `generatePrivateKey`/`privateKeyToAccount`. Consumer-controlled. |
| `uuid`, `jayson`                        | moderate          | `@solana/web3.js`                              | Same path, same reasoning.                                                                                                                                                                                             |
| `js-yaml`, `brace-expansion`, `esbuild` | high / high / low | dev toolchain (jest, tsup)                     | Build-time only; not shipped.                                                                                                                                                                                          |

**Do not run `npm audit fix --force`** — it resolves the `uuid` advisory by downgrading `@solana/web3.js` to `0.0.3`. `npm audit fix` (non-forced) is safe and clears the dev-toolchain entries.

Dependabot is configured weekly for npm and GitHub Actions. CI runs the full suite on Node 18 and 20 against real Redis, Postgres, and MySQL services.

---

## Recommended order of work

1. **H-1** — add versioning + CAS to `putUser`, and stop rewriting the whole record on login. Add a conformance case. _This should block the release._
2. **H-2** — normalize and bound wallet entries; add an abuse bucket not keyed on caller-supplied identity; warn when `allowedAppIds` is unset.
3. **M-3** — require PRF for biometric-primary and biometric-unlock; correct the security claims for gate mode; fix the test to assert the real property.
4. **M-4** — pin the Ledger off-chain envelope in `UserData` and derive from the pinned layout.
5. **M-1** — allow N concurrent challenges per account; charge `/challenge` to the requester rather than the target.
6. **M-2** — document the unverified-email boundary, or add a `verifyEmail` hook.
7. **L-1, L-2, L-4** — one-line fixes each (`Object.create(null)`, thread config through `authHeaders`, `no-store`).
8. **L-3, L-5** — follow from the fixes above; document the residual.

`README.md`, `SECURITY.md`, and `CHANGELOG.md` are currently empty files. `SECURITY.md` in particular should carry the threat model that the source comments already articulate well — the memory-only vault, the XSS boundary, the unverified-email boundary (M-2), and the gate-mode caveat (M-3).

---

## Appendix — reproduction

Findings H-1, H-2, M-1, M-2, L-1 and L-3 were reproduced with a temporary Jest harness driving the real `createAuthHandlers` / `createNextAuthRoutes` over `KvAuthStore(MemoryAdapter)` — the same code path a production deployment runs, with only the backend swapped for the normative in-memory reference. The harness was removed after the run; the working tree is unmodified apart from this document.

Assertions were written to express the _secure_ expectation, so a failing assertion is a confirmed defect:

| Assertion                                                | Result                                  |
| -------------------------------------------------------- | --------------------------------------- |
| A record stays under 5 MB after one anonymous register   | **fail** — 6.53 MB                      |
| ≤ 10 anonymous registers accepted per window             | **fail** — 40/40 accepted               |
| Unknown `appId`s rejected                                | **fail** — 4/4 minted                   |
| Imported wallet survives a concurrent login              | **fail** — lost                         |
| Two concurrent imports both survive                      | **fail** — one lost                     |
| Prototype-key routes return 404                          | **fail** — non-`Response` / `TypeError` |
| Victim's login survives an attacker's challenge refresh  | **fail** — 401                          |
| Victim can still get a challenge after 10 anonymous hits | **fail** — 429                          |
| Victim can register their own email                      | **fail** — 409, then 401 on login       |
