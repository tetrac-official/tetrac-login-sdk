# Security Audit — `@tetrac/login-sdk` v0.6.0

| | |
|---|---|
| **Target** | `@tetrac/login-sdk` — non-custodial authentication SDK (email/passkey, Web3 wallet, WebAuthn PRF biometric) |
| **Version** | 0.6.0 |
| **Commit** | `75577fa542d4201ca1521b7557e3c793732672b7` (branch `v0.5.1`) |
| **Date** | 2026-08-08 |
| **Scope** | Full `src/` tree — 9,902 LOC across core, server, client, react, ui, ledger, storage (KV + SQL). Build config, CI workflow, and dependency graph included. |
| **Method** | Manual source review of every module, threat-model reconciliation against `SECURITY.md`, and executable proof-of-concept for each finding (run against the SDK's own handlers and stores). Existing suite executed: **637 passing, 12 skipped** (skips require Docker engines). |
| **Out of scope** | Consuming applications, deployed infrastructure, the Ledger device firmware, and the cryptographic primitives inside `@noble/hashes` / WebCrypto (used, not re-implemented). |

---

## 1. Executive summary

This is an unusually well-defended codebase. The design decisions that matter most for a
non-custodial key system are correct and, in most cases, correct *for the stated reason*:
wallet secrets are AES-256-GCM sealed under a key the server never receives, sessions are
persisted only as SHA-256 digests, challenges are single-use and atomically consumed,
wallet signatures are origin-bound against server configuration rather than request input,
and every registration now proves possession of the identity key it claims. The storage
layer has been refactored into per-field writes specifically to eliminate the lost-update
class that destroys wallet keys, and the SQL dialects encode engine-specific hazards
(MySQL collation and truncation, Supabase's world-readable `public` schema, web-served
SQLite files) as boot-time refusals rather than documentation.

Nine findings are reported. **None permit authentication bypass, key recovery from the
server, or cross-tenant data access.** The most serious, F-1, is a data-destruction path:
an error-swallowing `catch` in the SQL store converts a transient backend failure into
"this account does not exist", and the `connect-wallet` handler responds to that by
re-creating the record — overwriting the only copy of the user's encrypted wallet keys.
The remainder are availability and hygiene issues, with two (F-2, F-4) allowing an
unauthenticated attacker to deny authentication or registration cheaply and remotely.

A recurring theme is worth naming: the codebase reasons very carefully about *deliberate*
failure modes and much less carefully about *incidental* ones. Every finding below except
F-3 arises where a control that is precisely designed for the adversarial case
(rate limiting, fail-closed reads) behaves differently on an error path, an unusual input
shape, or a caller-named identifier.

### Findings at a glance

| ID | Severity | Component | Summary |
|---|---|---|---|
| [F-1](#f-1) | **High** | `storage/sql/engine.ts` | Backend errors are swallowed into "account not found"; `connect-wallet` then re-creates the record and permanently destroys stored wallet keys |
| [F-2](#f-2) | **Medium** | `server/routes.ts` | `/register` charges a rate-limit bucket keyed on a caller-supplied email *before any proof* — an unauthenticated attacker can lock a named user out of sign-in |
| [F-3](#f-3) | **Medium** | `server/routes.ts` | `authMethod` is the only persisted field with no validation: arbitrary type and unbounded length reach permanent storage and every client |
| [F-4](#f-4) | **Medium** | `server/routes.ts`, `core/config.ts` | The deployment-wide account-creation ceiling has no key to rotate — and therefore no defence: 2 requests/minute deny registration to everyone |
| [F-5](#f-5) | Low | `server/routes.ts` | `/challenge` writes storage for any well-formed public key, registered or not; rotating the key resets the bucket |
| [F-6](#f-6) | Low | `server/http.ts` | The `x-real-ip` fallback ignores `trustedProxyHops` and fails open where the code's own principle is to return `null` |
| [F-7](#f-7) | Low | `core/config.ts` | The global per-IP bucket (10/60s across all endpoints and apps) throttles ~2 sign-ins per minute per egress IP — NAT and carrier-grade NAT users collide |
| [F-8](#f-8) | Low | `package.json` | Required peer dependencies carry published advisories (`viem` → `ws`, high; `@solana/web3.js` → `jayson` → `uuid`, moderate) |
| [F-9](#f-9) | Informational | `server/http.ts` | The 128 KB body cap is applied after the whole body is buffered, and measures UTF-16 code units rather than bytes |

Two further observations are recorded in [§5 Residual risks](#5-residual-risks-accepted-by-design)
rather than as findings, because they are explicit, documented design positions:
the bearer token in `localStorage`, and email as a non-verified index.

### Severity model

| Severity | Meaning |
|---|---|
| **Critical** | Key recovery, authentication bypass, or cross-tenant compromise, remotely and unauthenticated |
| **High** | Unrecoverable data loss, or compromise requiring a plausible precondition |
| **Medium** | Meaningful denial of service or integrity impact, cheaply reachable |
| **Low** | Limited impact, or requires a misconfiguration the SDK already warns about |
| **Informational** | Hardening; no direct exploit path identified |

---

## 2. Detailed findings

<a id="f-1"></a>
### F-1 — Swallowed backend errors destroy encrypted wallet keys · **High**

**Component** `src/storage/sql/engine.ts:87-111`, reached via `src/server/routes.ts:790-823`
**CWE** CWE-755 (Improper handling of exceptional conditions) → CWE-99/CWE-471 downstream data loss

#### What is wrong

`SqlAuthStore.getUser()` wraps *two* operations in one `try`: the `JSON.parse` of the
profile column, and a second round trip to the wallets table.

```ts
try {
  const user = JSON.parse(String(row.data)) as UserData;
  const ws = await this.run(this.driver,
    `SELECT data FROM ${t.userWallets} WHERE app_id = ? AND public_key = ?`, [appId, publicKey]);
  user.wallets = sortWalletsBySlot(...);
  return user;
} catch {
  return null; // malformed value — fail safe rather than throwing
}
```

The comment describes the intent — tolerate a malformed value — but the `catch` also
captures every failure of the wallets query: a dropped connection, a pool timeout, a
statement timeout, a transient replica error. The store's own contract forbids exactly
this. From `src/storage/store.ts:107-110`:

> **ERRORS FAIL CLOSED. Propagate them. `null` means "the backend answered, and it is
> absent" — NEVER "the backend did not answer".**

`getUser` violates the invariant it documents.

#### Why it destroys data

`connectWallet` treats `null` as "this wallet has never registered here" and takes the
creation branch:

```ts
let user = await getUserByPublicKey(store, appId, body.publicKey);
const isNew = !user;
if (!user) {
  user = { appId, publicKey: body.publicKey, authMethod: "wallet", wallets, ... };
  await persistUser(store, user);          // ← whole-record write
}
```

`persistUser` → `SqlAuthStore.putUser` upserts each wallet slot with
`ON CONFLICT (app_id, public_key, chain, role) DO UPDATE SET data = ?`. The client always
sends a *freshly generated* bundle on `connect-wallet` (`generateWalletBundle` mints new
keypairs every call), so the upsert replaces the stored ciphertext of every slot in that
bundle with the ciphertext of brand-new, empty wallets.

`encryptedSecret` is the only copy of that private key. There is no escrow, no backup, and
no re-derivation. Any balance at the old address is stranded permanently, and both the
failing request and the destructive one return `2xx`.

The trigger is a *transient* error, but the damage is permanent and silent. The same
`catch` also fires on a genuinely malformed profile row, with identical consequences —
so the "fail safe" path is not fail-safe at all on the write side.

#### Proof of concept

Run against the real SQLite store, with a driver that fails only the wallets `SELECT`
(simulating a connection reset mid-request):

```
getUser during backend error: null
second connect status: 201            ← treated as a brand-new account
stored secret now: iv:REGENERATED-CIPHERTEXT
```

The record previously held `iv:ORIGINAL-CIPHERTEXT`. One failed inner query, and it is gone.

#### Scope

- **SQL backends (Postgres/Supabase, MySQL, SQLite): full exposure**, since the wallets
  query is inside the `try`.
- **KV backends (Redis/Upstash/Vercel KV): partial.** `KvAuthStore.getUser` performs its
  `hgetall` *outside* the `try`, so a backend error correctly propagates. A malformed
  stored value still yields `null` and the same overwrite.

#### Recommendation

Two independent fixes; apply both.

1. **Narrow the `catch` to what it claims to handle.** Move the wallets query out of the
   `try`, or catch only `JSON.parse`:

   ```ts
   let user: UserData;
   try { user = JSON.parse(String(row.data)) as UserData; }
   catch { return null; }                     // genuinely malformed profile
   const ws = await this.run(...);            // errors propagate, per the contract
   ```

2. **Make record creation non-destructive.** A false "absent" must never be able to
   overwrite. Add a create-if-absent write to the `AuthStore` port
   (`ON CONFLICT DO NOTHING` / `HSETNX`-style) and use it on the creation branches of
   `connectWallet` and `register`, reserving the whole-record upsert for paths that have
   proven the record's prior state. This turns the failure mode from silent key loss into
   a benign conflict the handler already knows how to answer (`409`).

Optionally, add a conformance case asserting that a store whose backend throws propagates
rather than returning `null` — the suite currently covers absence and expiry, but not
failure.

---

<a id="f-2"></a>
### F-2 — `/register` rate limit locks a named victim out of sign-in · **Medium**

**Component** `src/server/routes.ts:555-560`
**CWE** CWE-770 (Allocation without limits or throttling) / CWE-645 (Overly restrictive account lockout)

#### What is wrong

`/register` charges its rate-limit bucket before any verification, keyed on an identifier
lifted straight from the request body:

```ts
const limited = await rateLimited(req, {
  endpoint: "register", appId,
  identifier: bucketId(body.email ?? body.publicKey),
});
if (limited) return limited;
// …only now: existence checks, authPublicKey check, signature verification
```

The codebase fixed precisely this pattern elsewhere and documented why. `/login` verifies
first and charges only on failure (`routes.ts:674-694`, "an attacker spamming failed logins
for a victim's email cannot lock the victim out"). `/challenge` charges the *requester*
when a trustworthy IP exists and only falls back to the target bucket otherwise
(`routes.ts:418-448`, "charging the TARGET is backwards"). `/register` received neither
treatment, and unlike `/challenge` it charges the target bucket **even when
`trustProxyHeaders` is enabled**.

#### Why it matters

The shipped `<LoginPanel>` defaults to `emailMode: "auto"` (`src/ui/LoginPanel.tsx:20`),
and the documented auto flow registers first and falls back to login **only** on
`"already exists"` (`src/ui/EmailMethod.tsx:144-159`):

```ts
try { result = await registerWithEmail({ email, passkey }); }
catch (err) {
  if (!String(err).includes("already exists")) throw err;   // 429 → rethrow
  …
}
```

So a returning user's normal sign-in traverses `/register` first, and a `429` there is
terminal — the client never reaches `/login`.

An unauthenticated attacker who knows a victim's email address sends ~11 requests per
60-second window carrying `{ publicKey: <any valid base58>, email: "victim@…" }`. No
signature, no challenge, no key. Every one is rejected (`409`), and every one is counted.
The victim is then unable to sign in for as long as the attacker keeps up ~10 requests per
minute. With `trustProxyHeaders` enabled the attacker's own IP bucket (10/60s) means two
source addresses suffice.

#### Proof of concept

```
attacker statuses: 409,409,409,409,409,409,409,409,409,429,429
victim auto-register: 429 {"error":"Rate limit exceeded"}
```

The victim's client sees `Rate limit exceeded`, which does not match `already exists`, so
the fallback to `loginWithEmail` never runs.

#### Recommendation

Apply the `/login` treatment: **charge on failure, not on arrival.** Move the
`register` bucket check below the collision checks and the signature verification, so only
requests that fail to prove possession feed the counter. A returning user's `409` should
cost nothing — the code already reasons this way for the *account-creation* ceiling
(`routes.ts:615-619`), just not for this bucket.

Separately, make the client resilient: `EmailMethod`'s auto flow should fall back on a
`409` *status* rather than a substring match on the error message, and should surface a
`429` distinctly.

---

<a id="f-3"></a>
### F-3 — `authMethod` is persisted unvalidated, unbounded, and untyped · **Medium**

**Component** `src/server/routes.ts:513-636`
**CWE** CWE-20 (Improper input validation) / CWE-400 (Uncontrolled resource consumption)

#### What is wrong

`register` validates every persisted field it accepts — `publicKey` (canonical base58,
32 bytes), `email` (typed, ≤320, format), `appId` (charset + length + optional allowlist),
`authPublicKey` (64 hex), `pbkdf2Iterations` (integer within a pinned band),
`offchainEnvelope` (closed union) — and rebuilds `wallets[]` from an explicit allowlist
with the comment:

> REBUILD from an allowlist — never persist the caller's object. […] a single anonymous
> `/register` carrying `{…, junk: "x".repeat(5_000_000)}` persisted 5 MB.

`authMethod` bypasses all of it:

```ts
authMethod: body.authMethod ?? "email",
```

There is no type check, no length bound, and no membership test against the
`AuthMethod = "email" | "wallet" | "biometric"` union. The value is written into the
profile JSON, persisted permanently, and returned to every client by `/user-data`,
`/register`, `/login`, `/login-wallet`, and `/connect-wallet`.

#### Impact

1. **Storage bloat with permanent residency.** The only bound is `MAX_BODY_BYTES` (128 KB).
   Each created account can carry ~60 KB of attacker-chosen text in a field that is never
   expired or swept, and the global creation ceiling (2/minute) is the *only* brake — that
   is ~170 MB/day of permanent records, at a cost of two requests per minute. This is the
   exact vector the `wallets[]` allowlist rebuild exists to close, left open one field over.
2. **Type confusion in consuming applications.** `authMethod` can be an object, array,
   number, or boolean. The SDK's own React layer branches on it —
   `useActiveWallet` and `useWallets` gate the Web3 identity rule on
   `user?.authMethod === "wallet"`, and `<ExportKeyPanel>` selects the re-auth ceremony from
   it. A non-string simply falls through to the embedded-wallet branch here, but a
   consuming app doing `authMethod.toUpperCase()` or `authMethod.startsWith(…)` gets a
   runtime throw on a record an anonymous caller controls.
3. **The server's own guard is weakened.** `connectWallet` fails closed on
   `user.authMethod !== "wallet"`, which is correct — but the field it is testing is
   caller-authored, so the guard's meaning depends on a value the SDK never constrained.

An attacker can only set this on records whose identity key they hold (registration proves
possession, correctly), so this is not an impersonation path — it is a resource and
integrity issue.

#### Proof of concept

```
bloat register status: 201  stored length: 60000
object authMethod: 201 {"evil":true}
```

Both records persist and both round-trip to the client.

#### Recommendation

Validate it like every neighbouring field, and treat absence as `"email"` as it does today:

```ts
const AUTH_METHODS = ["email", "wallet", "biometric"] as const;
function validAuthMethod(v: unknown): v is UserData["authMethod"] {
  return typeof v === "string" && (AUTH_METHODS as readonly string[]).includes(v);
}
if (body.authMethod != null && !validAuthMethod(body.authMethod)) {
  return error("Invalid authMethod", 400);
}
```

While there: `readWallets` bounds `publicKey` to 128 characters but does not check that it
is a plausible address for the declared chain, nor that `encryptedSecret` matches the
`iv:ct` shape `decryptSecret` requires. Both are self-inflicted for the record's owner, so
they are hardening rather than a finding — but the same allowlist discipline applies.

---

<a id="f-4"></a>
### F-4 — The global account-creation ceiling is a deployment-wide denial-of-service lever · **Medium**

**Component** `src/server/routes.ts:307-314`, `src/core/config.ts:156-174`
**CWE** CWE-770

#### What is wrong

Account creation is capped by one bucket with no key at all:

```ts
await checkRateLimit(store, { endpoint: "create", identifier: "global" },
                     config.accountCreationRateLimit);   // default 2 per 60s
```

The reasoning is sound and explicitly stated: every other bucket keys on a caller-supplied
email or public key, so an attacker rotating either gets a fresh counter and the limit
never fires. A global counter "has no key to rotate."

The consequence, however, is symmetric and is not stated: **the defender has no key
either.** Any unauthenticated party can hold this bucket exhausted indefinitely at
2 requests per minute, and registration is then closed for every legitimate user of the
deployment. The attacker's cost is a fresh keypair, a `/challenge` round trip, and a
signature — all free and all scriptable — and the ceiling is charged *after* a valid
signature precisely so that only genuine creations consume it, which means the attacker
simply creates two throwaway accounts a minute.

There is no IP dimension to fall back on: with the default `trustProxyHeaders: false`
there is no client IP at all, and even with it enabled the creation bucket is checked
independently of the IP bucket.

`config.accountCreationRateLimit` is documented as "a capacity number, not a security dial"
— but it *is* the security dial, and raising it to accommodate real signup volume widens
the storage-bloat window (see F-3) proportionally.

#### Recommendation

A single global counter cannot be both the anti-abuse control and a service the deployment
depends on. Restructure it as a *ceiling above* a discriminating control rather than as the
only control:

- Keep the global bucket, but size it to genuine capacity (well above expected peak) so it
  functions as a backstop against runaway abuse rather than as the primary throttle.
- Add a per-IP creation bucket where a trustworthy IP exists, and document that
  `trustProxyHeaders` is what makes creation limiting meaningful.
- For deployments that cannot supply an IP, expose a hook so integrators can require a
  proof-of-work, CAPTCHA, invite code, or verified email before `/register` is reachable —
  `SECURITY.md` already tells them to gate `/register` behind their own verification if
  email must mean identity; the same hook solves this.
- At minimum, surface the exhaustion distinctly (a boot warning or a dedicated error code)
  so an operator can tell "we are under attack" from "we are popular today". Both currently
  return the same 429.

---

<a id="f-5"></a>
### F-5 — `/challenge` writes storage for unregistered public keys, with a rotatable bucket · **Low**

**Component** `src/server/routes.ts:405-511`

`/challenge` short-circuits an unknown *email* to an unstored dummy — a well-judged fix for
the enumeration oracle. An unknown *public key* takes the opposite path: the handler never
checks that the key corresponds to a record, and issues and **stores** a real challenge for
it.

```ts
let publicKey = body?.publicKey ?? null;
if (!publicKey && body?.email) publicKey = await resolvePublicKeyByEmail(...);
…
const challenge = await issueChallenge(store, appId, publicKey, config);   // unconditional
```

Because the per-identifier bucket is keyed on the supplied public key, an attacker who
generates a fresh keypair per request gets a fresh counter every time — the same rotation
problem the global creation ceiling exists to solve, applied here to storage writes rather
than records.

**Proof of concept:** 100 unauthenticated requests with 100 rotated public keys produced
100 stored challenge keys and zero `429`s.

Each key carries a 300-second TTL, so the resident set is bounded by
`rate × 300s` rather than growing without limit — 1,000 req/s sustains ~300,000 live keys,
plus one rate-limit counter per identifier at a 60-second TTL. On a SQL backend those are
rows in `ttc_challenges` and `ttc_rate_limits` that only `sweepExpired` reclaims, and the
rate-limit rows embed the identifier.

**Recommendation.** Issue a stored challenge only for a public key that resolves to a
record, and answer an unknown key the way an unknown email is already answered: a
well-formed, unstored dummy. The response shape stays identical, so no existence signal is
introduced — and `/register`'s possession proof still works, because that path fetches a
challenge for a key it is about to create.

If that ordering is inconvenient (registration legitimately needs a challenge for a key
with no record yet), the alternative is to make the unauthenticated challenge path
requester-keyed unconditionally, or to require the account-creation ceiling to be charged
before a challenge is minted for an unknown key.

---

<a id="f-6"></a>
### F-6 — `x-real-ip` fallback bypasses `trustedProxyHops` and fails open · **Low**

**Component** `src/server/http.ts:42-54`

```ts
if (fwd) {
  const parts = fwd.split(",").map(p => p.trim()).filter(Boolean);
  const idx = parts.length - 1 - trustedProxyHops;
  if (idx >= 0 && parts[idx]) return parts[idx]!;
}
return req.headers.get("x-real-ip") ?? null;
```

When `x-forwarded-for` is present but carries **fewer entries than `trustedProxyHops + 1`**
— i.e. exactly the case where the request did not traverse the expected proxy chain — the
function does not return `null`. It falls through to `x-real-ip`, a header the caller
controls in that scenario.

This contradicts the module's own stated principle, argued at length two comments above:

> `null`, NOT a `"unknown"` sentinel. […] Returning `null` makes "no usable IP" impossible
> to mistake for an identity.

The consequence is that a caller who can reach the origin outside the proxy chain chooses
their own bucket key. Because the IP bucket is deliberately **global across every endpoint
and every app**, naming a victim's IP throttles that IP everywhere at 10 requests per
60 seconds.

A correctly-fronted deployment never produces a short chain, so this requires the
misconfiguration `SECURITY.md` already warns about (`trustProxyHeaders` on a directly
reachable app). It is reported because the fallback silently *undoes* the `trustedProxyHops`
setting the operator chose, which is not obvious from either the code or the documentation.

**Recommendation.** Treat a chain shorter than the configured hop count as "no trustworthy
IP" and return `null`. Consult `x-real-ip` only when `x-forwarded-for` is absent entirely,
and only when `trustedProxyHops === 0`.

---

<a id="f-7"></a>
### F-7 — The global IP bucket throttles roughly two sign-ins per minute per egress IP · **Low**

**Component** `src/core/config.ts:211-214`, `src/server/routes.ts:257-273`

The IP bucket is checked on every rate-limited route, is keyed on the IP alone (no
endpoint, no `appId`), and uses the general `rateLimit` config — **10 requests per 60
seconds, for everything**.

One `"auto"`-mode email sign-in costs four counted requests:
`/challenge` (possession proof) → `/register` → `/challenge` → `/login`. A Web3 connect
costs two. So a single egress IP supports about two sign-ins per minute before legitimate
users receive `429`.

That is fine for residential IPs and wrong for the population that shares one: corporate
NAT, university networks, carrier-grade NAT on mobile, and VPN exit nodes. Those users see
intermittent, unexplained `Rate limit exceeded` during normal sign-in, and the failure is
indistinguishable from an outage.

The global scoping is intentional ("one abusive IP is throttled everywhere at once") and
worth keeping. The *default value* is the problem: 10/60s was chosen for per-endpoint,
per-identifier buckets and is reused unchanged for a bucket that aggregates all traffic
from an address.

**Recommendation.** Give the IP bucket its own config entry with a substantially higher
default (100/60s is still a strong abuse signal while accommodating ~25 concurrent sign-ins
from one NAT), and document the sizing relationship: the IP ceiling should exceed
`requests-per-sign-in × expected concurrent users per egress IP`. Consider counting only
failed or state-changing requests against it.

---

<a id="f-8"></a>
### F-8 — Advisories in required peer dependencies · **Low**

**Component** `package.json`

The SDK's own runtime dependency footprint is exemplary — a single package,
`@noble/hashes@2.2.0`, with `npm audit --omit=dev` reporting **0 vulnerabilities**.

However, `viem`, `@solana/web3.js`, and `tweetnacl` are declared as **non-optional** peer
dependencies, so every consumer installs them and inherits their transitive graph:

| Advisory | Severity | Path | Status |
|---|---|---|---|
| [GHSA-96hv-2xvq-fx4p](https://github.com/advisories/GHSA-96hv-2xvq-fx4p) — `ws` memory-exhaustion DoS | **High** | `viem ≤ 2.54.1` → `ws 8.0.0–8.20.1` | **Fixable.** The peer range `^2.46.0` already permits a fixed `viem`; the pinned devDependency (`^2.46.1`) does not resolve to one. |
| [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) — `uuid` missing buffer bounds check | Moderate | `@solana/web3.js ≤ 1.98.4` → `jayson` → `uuid < 11.1.1` | **Not fixable in the v1 line.** Only reachable via `uuid` v3/v5/v6 with a caller-supplied `buf`, which `jayson` does not do. |

Dev-toolchain advisories (`brace-expansion`, `js-yaml`, `esbuild`) affect the build and test
environment only and do not ship — `files: ["dist"]` is correctly scoped.

**Recommendation.**
1. Raise the `viem` peer floor past the `ws` fix and bump the devDependency to match, so
   `npm install` on a fresh consumer resolves a clean tree.
2. Record the `@solana/web3.js` v1 advisory as an accepted risk in `SECURITY.md` with the
   reachability rationale above, so downstream `npm audit` output has an answer.
3. Consider adding `npm audit --omit=dev` to CI as a non-blocking report, so a *runtime*
   regression is caught while dev-only noise stays out of the way.

---

<a id="f-9"></a>
### F-9 — The body cap is applied after buffering, and counts UTF-16 units · **Informational**

**Component** `src/server/http.ts:70-80`

```ts
const declared = Number(req.headers.get("content-length"));
if (Number.isFinite(declared) && declared > maxBytes) return null;
const text = await req.text();          // ← buffers the whole body first
if (text.length > maxBytes) return null;
```

Two gaps, both minor:

- `content-length` is only a hint, as the comment says — but the fallback measurement
  happens *after* `req.text()` has already materialised the entire stream. A chunked request
  with no `content-length` is buffered in full before the 128 KB check runs. In practice the
  hosting platform's own body limit (Vercel: 4.5 MB) bounds this, so the exposure is
  platform-dependent rather than unbounded.
- `String.length` counts UTF-16 code units. A body of 128,000 three-byte characters is
  ~384 KB on the wire and passes.

**Recommendation.** Read the body through its stream and abort once the cumulative byte
count exceeds `maxBytes`, or measure with `new TextEncoder().encode(text).byteLength` if
retaining the simpler shape. Note the platform-limit dependency in `SECURITY.md`.

---

## 3. Verified controls

The following were examined specifically and found correct. They are listed because an
audit that reports only defects misrepresents the codebase, and because a future change to
any of them should be treated as security-relevant.

**Cryptography**
- Wallet secrets: AES-256-GCM via WebCrypto, fresh 96-bit CSPRNG IV per encryption, auth tag
  enforced on decrypt, no CBC compatibility path. Ciphertext format `iv:ct+tag` (b64url).
- Email app key: PBKDF2-HMAC-SHA256 over a domain-separated salt `SHA-256(appId : email)`.
  Default 600k iterations (OWASP 2023), pinned per user at registration, and **bounded
  server-side** to `[100k, 1M]` so a malicious client cannot pin a weak count.
- Auth keypair: ed25519 seeded from `SHA-256("ttc-auth-v1:" + appKey)` — properly
  domain-separated from the encryption key, so the auth key cannot be worked backwards into
  the vault key.
- Session tokens: 256-bit CSPRNG; storage sees only `SHA-256(token)`, both as the key and as
  the record pointer. A bare hash is the correct construction for a uniform 256-bit secret,
  and the code argues this correctly rather than reaching for a KDF.
- Biometric: WebAuthn PRF only, with no fallback. The wrap key is HKDF-SHA-256 of the PRF
  output, never the raw secret. The decision to delete the previous "gate" mode — where a
  non-extractable `CryptoKey` in IndexedDB preserved the *decryption capability* even though
  the key bytes were protected — is the right call and correctly reasoned.
- `timingSafeEqual` folds the length difference into the accumulator and scans the full
  window without relying on `NaN` propagation.
- CSPRNG discipline throughout: `crypto.getRandomValues` only, with an explicit throw if
  unavailable. `generateStrongPasskey` uses big-integer base58 long division, so there is no
  modulo bias, and clamps to a 128-bit floor with NaN/fractional inputs normalised before
  allocation.

**Authentication and session handling**
- Every registration proves possession of the identity key before a record is created —
  closing the record-planting attack where an attacker claimed a victim's on-chain address
  with `authMethod: "email"` and planted deposit addresses.
- Signature verification precedes challenge consumption on every path, so a forged
  signature cannot burn a victim's in-flight challenge.
- Challenges are per-value (`challenge:{appId}:{pk}:{value}`), so issuing one cannot
  invalidate another mid-signature; consumption is a single atomic `GETDEL` /
  `DELETE … RETURNING` / `SELECT FOR UPDATE` transaction, and the presented value is
  validated to 64 hex characters before it ever reaches a key.
- Wallet login messages are SIWE-shaped and bound to `config.origin` taken from **server**
  configuration, never from the request; the client builds the counterpart from
  `window.location.origin`, not from config, which is what defeats the hostile-page
  key-harvesting attack.
- `verifySession` treats the record's `authTokenHash` pointer as the authority, not the mere
  existence of a session key — which closes the concurrent-login race where the pointer
  loser kept an unreachable but fully working token until TTL.
- Auth is header-based with custom headers (`ttc-auth-token`), so the API carries no ambient
  authority and is not CSRF-exposed; `cache-control: no-store` is set on every response.
- `logout` is constant in shape and never reveals whether the presented token was valid.
- `/login` and `/login-wallet` verify first and penalise only on failure.

**Storage layer**
- The `AuthStore` port's three invariants (expiry enforced on read, atomic challenge
  consume, errors fail closed) are the right three, and the conformance suite tests them
  against real engines in CI (Redis, Postgres, MySQL) rather than mocks.
- Per-field writes (`putWalletSlot`, `setSessionPointer`) eliminate the lost-update class
  that previously destroyed wallet keys when a login raced an import.
- The email index claims rather than overwrites (`HSETNX` / read-then-insert inside a
  transaction), surfacing `EmailTakenError` instead of silently orphaning an account.
- The rate-limit `CASE` in the SQL upsert correctly restarts an expired window — the
  permanent-lockout bug is genuinely closed, and `countOrFailClosed` refuses to treat an
  uncountable request as allowed.
- `hitRateLimit`'s KV implementation re-stamps the TTL exactly once past the cap, avoiding
  the self-extending-window DoS that firing on every over-limit hit produced.
- MySQL's three hazards are handled structurally: `VARBINARY` key columns (not
  `utf8mb4_bin`, which is `PAD SPACE`), `MEDIUMTEXT` blobs, and a preflight that refuses to
  boot outside strict mode. Postgres refuses the Supabase-exposed `public` schema
  case-insensitively. SQLite preflight rejects web-served paths and warns on loose file
  permissions.
- `sqliteDriver` serialises overlapping transactions through a promise chain rather than a
  depth counter — the correct fix, since `await` yields and a counter cannot distinguish
  re-entry from interleaving.
- All SQL is parameterised; identifiers come from dialect constants, and `LIMIT` values pass
  through `Math.max(1, limit | 0)`.

**Client and browser surface**
- The app key is memory-only on a `Symbol.for()`-keyed global — never in `localStorage` or
  `sessionStorage`, never transmitted — with idle auto-lock (15s), lock on visibility change,
  `freeze`, `pagehide`, and bfcache restore (`pageshow.persisted`), plus cross-tab lock
  propagation via a `storage` event.
- `useSigner` reads the app key **inside each callback at call time**, never captured at
  render, so a lock that races a render cannot let a stale key decrypt.
- Reveal always runs a fresh ceremony and derives a one-time key; it never arms the session,
  and `useExportKey` auto-clears after 30s with clipboard wipe in `<ExportKeyPanel>`.
- Signing helpers zero the derived secret-key buffers (`kp.secretKey.fill(0)`,
  `sk.fill(0)`) in `finally` blocks.
- No `eval`, `new Function`, `innerHTML`, `dangerouslySetInnerHTML`, or `document.write`
  anywhere in `src/` — verified. No secret is logged; the only `console` calls are boot
  warnings carrying configuration text.
- The passkey generator is on by default, auto-fills a ~192-bit value, and auto-reveals it
  with a save prompt — making the strong path the default path rather than an opt-in button.
- The 16-character passkey floor is enforced on registration paths only, so an account
  created before the floor existed is not locked out of its own wallets.

**Build and supply chain**
- One runtime dependency. `files: ["dist"]` — no source, tests, or configs published.
- `dist/` is git-ignored and not tracked.
- CI pins `permissions: contents: read`, runs the matrix against Node 18 and 20, and stands
  up real Redis, Postgres, and MySQL services; the conformance suite asserts `REDIS_URL` is
  set in CI so a missing service cannot silently reduce it to zero cases.
- No secrets, tokens, or credentials in the repository; `.env.example` contains only
  variable names.

---

## 4. Test coverage observations

637 tests pass across 60 suites; 12 are skipped pending Docker engines. Coverage is
notably adversarial — the suite names its own past vulnerabilities
(`rate-limit-sustained-lockout`, `record-lost-update`, `challenge-enumeration`,
`audit-h5-identity-binding`, `ciphertext-tampering`, `timing-safe-edge-cases`) and pins
each one. This is the right model, and it is why most of this audit's findings are on
error paths rather than on the primary flows.

Three gaps correspond to findings above and are worth closing with tests:

1. **No store-level failure test.** The conformance suite covers absence and expiry but
   never asserts that a *throwing* backend propagates. Adding that case to
   `storage/conformance.ts` would have caught F-1 in the SQL engine.
2. **No test that a `429` on `/register` leaves an existing account reachable.** The suite
   pins the equivalent property for `/login` (`rate-limit-self-extend`,
   `challenge-lockout`) and for the account-creation ceiling
   (`account-creation-limit`), but not for the register bucket (F-2).
3. **Field validation is tested per-field.** `audit-type-confusion.test.ts` enumerates
   non-string shapes for `email`, `publicKey`, and `appId` but not `authMethod` (F-3). A
   table-driven test over *every* persisted field would make the omission structural rather
   than a matter of remembering.

---

## 5. Residual risks (accepted by design)

These are correct positions, clearly documented, and are recorded here so a reader of this
report does not mistake them for oversights.

- **Script execution on the origin defeats any browser key system.** The memory-only vault
  defeats storage scraping, not script execution: any JavaScript on the origin can call the
  same signing and reveal APIs during the unlocked window. `SECURITY.md` states this plainly
  and correctly promotes the consuming application's CSP to part of the SDK's security
  model.
- **The session token lives in `localStorage`** and is therefore readable by any script on
  the origin. This is a deliberate trade for a header-based, CSRF-immune API. The blast
  radius is bounded by single-active-session enforcement (each login revokes the previous
  token), a 24-hour TTL, and the fact that the token alone cannot decrypt any wallet — it
  yields ciphertext and public keys. Integrators handling higher-value accounts should
  enable `bindSessionToUserAgent` and shorten `sessionTtlSeconds`.
- **Email is a KDF salt and a storage index, not an identity claim.** First-caller-wins on
  an address is the intended semantic; anonymous and throwaway addresses are expected. Apps
  that need email to mean identity must gate `/register` behind their own verification.
- **`GET /search-wallet` is an existence oracle**, which is the endpoint's purpose.
- **`POST /challenge` is not constant-time** — the dummy response closes the trivial read,
  not the latency side channel.
- **`appId` and `origin` are immutable derivation input.** Changing either re-derives every
  app key and strands existing ciphertext. The boot warnings for `unrestricted_app_id` and
  `default_app_id` are the correct mitigation.

---

## 6. Prioritised remediation plan

| Priority | Action | Finding |
|---|---|---|
| 1 | Narrow the `catch` in `SqlAuthStore.getUser` to `JSON.parse` only, and add a create-if-absent write so a false "absent" can never overwrite a record | F-1 |
| 2 | Move `/register`'s rate-limit check below verification (charge on failure), and make the client's auto flow branch on status rather than message text | F-2 |
| 3 | Validate `authMethod` against the closed union | F-3 |
| 4 | Restructure the account-creation ceiling as a backstop above a discriminating control; add an integrator hook for proof-of-work / CAPTCHA / invite gating | F-4 |
| 5 | Issue stored challenges only for keys that resolve to a record; return the dummy otherwise | F-5 |
| 6 | Return `null` from `clientIp` when the XFF chain is shorter than `trustedProxyHops + 1` | F-6 |
| 7 | Give the global IP bucket its own, higher default and document the sizing relationship | F-7 |
| 8 | Raise the `viem` peer floor past the `ws` fix; record the `@solana/web3.js` v1 advisory as accepted with reachability rationale | F-8 |
| 9 | Bound the request body during streaming and measure bytes, not UTF-16 units | F-9 |
| 10 | Add the three test cases in §4 so each fix is pinned | F-1, F-2, F-3 |

---

## 7. Conclusion

The SDK delivers on its central claim: **a full database compromise yields ciphertext,
public keys, and email addresses — not wallet keys.** That claim was tested against the
code rather than taken from the documentation, and it holds. The server stores no
password-equivalent, no passkey, and no session token; authentication is proof-of-control
of a key, verified by signature; and every derivation path is domain-separated by `appId`
and, for Web3, by an origin the client cannot lie about.

No finding in this report undermines that property. F-1 is the one that warrants prompt
attention, because its consequence — the permanent, silent loss of the only copy of a
private key — is precisely the outcome the storage layer's per-field-write refactor was
built to prevent, reintroduced through an error path rather than a write path. The
remaining findings are availability and hygiene work.

The codebase's habit of writing the *reason* for a control next to the control is unusual
and materially raised the quality of this review; it is also what made the gaps findable,
since each one sits where a documented principle was applied on one path and not on an
adjacent one.

---

*Findings F-1 through F-5 were confirmed with executable proofs of concept run against the
SDK's own handlers and stores at the audited commit. The verification suite was removed
after use and is not part of the repository; the observed output is quoted inline with each
finding.*
