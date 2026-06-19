# Feature PRD — multi-app Upstash isolation via `appId` server-side namespacing (`0.4.0`)

Make `appId` a **first-class server-side dimension** so multiple apps can safely share **one** Upstash/Redis
database on a single Vercel project. Today `appId` exists in `AuthConfig` but is used **client-side only**
(it salts key-derivation); the Redis keyspace is global, so two apps pointed at the same DB collide on
`pubKey:`, `email:`, `session:`, and `challenge:` keys. This PRD turns the public-key identifier into an
**`appId`-scoped** record and turns the email index into a **`{ appId: publicKey }` map** — exactly the
`pubkey: { appid: users_public_key, appid2: same_user_public_key }` shape requested — and threads `appId`
through the `register`, `login`, `loginWallet`, `connectWallet`, and `challenge` routes.

- **Status:** ✅ Implemented for `0.4.0`. This file documents the delivered design.
- **Shape:** **BREAKING.** Changes the Redis key scheme and the request contract (adds an optional `appId`
  that defaults to `config.appId`). Needs a **fresh security audit** (see §9).
- **Migration:** **None.** Per product decision, existing records are **not** migrated — `0.4.0` is a clean
  slate. §7 below is retained for reference but was intentionally **not shipped** (no migration script, no
  legacy dual-read shim).
- **Driver:** Operational — run N apps on one Vercel deployment + one Upstash DB without per-app DBs.
- **Filename note:** created as `features/upstash-multiple-apps-0.4.0.md` (the requested
  `upstash-multiple-apps-0.4.0md` was missing the `.` before `md`).
- **Verification:** `tsc --noEmit` + `prettier --check` clean; `jest` 267/267 green (new
  `tests/multi-app.test.ts`, `tests/storage-hash.test.ts`); `npm run smoke:multiapp` green against `dist/`.

---

## 1. Motivation — the gap this closes

`appId` is documented as the cross-app isolator, but the isolation is **only in client-side key
derivation**, never in storage:

- Email/passkey: `salt = SHA-256(appId : email)` → `appKey = PBKDF2(passkey, salt, iters)`
  (`src/core/crypto.ts`, `src/core/config.ts:54-65`).
- Wallet: the signed unlock message embeds `App: {appId}` → `appKey = SHA-256(signature)`
  (`src/core/index.ts`).

The **server** never sees or stores `appId`. Every record is global:

| Key (today) | Value | Source |
|---|---|---|
| `pubKey:{publicKey}` | `JSON(UserData)` | `src/server/session.ts:26` |
| `email:{email}` | `publicKey` (string) | `src/server/session.ts:28` |
| `challenge:{publicKey}` | challenge string | `src/server/challenge.ts` |
| `session:{token}` | `publicKey` or `publicKey\|fp` | `src/server/session.ts:73` |
| `ratelimit:{identifier}` | counter | `src/server/rateLimit.ts` |

### 1.1 Concrete collisions when two apps share one Upstash DB

1. **Wallet user, two apps (data-integrity break).** A user connects wallet `W` on **App A** →
   `pubKey:W = UserData_A` whose `wallets[]` are encrypted with App A's appKey. The same user connects `W`
   on **App B**: `connectWallet` finds the existing `pubKey:W`
   (`src/server/routes.ts:365`), treats them as a returning user, and issues a session over `UserData_A`.
   App B re-derives a **different** appKey (its `appId` differs) and **cannot decrypt** those wallets. The
   self-heal/backfill branch (`routes.ts:375-381`) makes it worse by mixing bundles.

2. **Email user, two apps (false 409).** A user registers `alice@example.com` on **App A** →
   `email:alice@example.com = pubKeyA`. They try to register the same email on **App B**: register reads the
   global `email:` index (`routes.ts:237-240`), sees it exists, and returns **409 "Account already
   exists"** — even though the user has *no* account on App B.

3. **Challenge clobber.** `challenge:{publicKey}` is global, so a challenge App A issues for wallet `W` and
   one App B issues for the same `W` overwrite each other (last write wins) — a cross-app liveness foot-gun.

4. **Session bleed.** A `session:{token}` minted by App A verifies on App B (same DB, same token keyspace) —
   a token issued in one app's trust context is honored by another.

**Goal:** one Upstash DB, N apps, **zero** cross-app collision or bleed, with `appId` supplied per request.

---

## 2. Current state (precise)

- **Identity = the public key.** `pubKey:{publicKey} → UserData` is the *primary* record; the public key is
  the Redis key (`session.ts:32-44`). Email is a *secondary* pointer `email:{email} → publicKey`
  (`session.ts:46-52`).
- **Register** (`routes.ts:191-272`): validates `publicKey` (Solana ed25519, canonical base58,
  `routes.ts:48-62`), optional `email`/`authPublicKey`, checks `pubKey:` then `email:` for collisions,
  verifies wallet signatures, then `persistUser` + `issueSession`.
- **Login** (`routes.ts:274-301`): `email → publicKey → UserData`, verify `authPublicKey` signature over a
  single-use challenge, issue session.
- **loginWallet / connectWallet** (`routes.ts:303-384`): key directly off `publicKey`.
- **Config** (`config.ts`): `appId: "ttc"` default; `keyPrefixes` are flat `prefix + id`.
- **`StorageAdapter`** (`src/storage/adapter.ts`): `get/set/del/incr/expire/getdel` — **string ops only, no
  hash ops** (relevant to §3.2).

---

## 3. Proposed design

Two coordinated changes: **(A)** namespace every per-app key by `appId`, and **(B)** turn the email index
into a per-app `{ appId: publicKey }` map (the requested shape). `appId` arrives **per request**, is
**validated**, and is **pinned into `UserData`** so every record is self-describing.

### 3.1 New key scheme (A — namespacing)

Insert `appId` as a namespace segment between the existing prefix and the identifier:

| Concern | Key (today) | Key (`0.4.0`) | Value |
|---|---|---|---|
| User record | `pubKey:{publicKey}` | `pubKey:{appId}:{publicKey}` | `JSON(UserData)` (now incl. `appId`) |
| Email identity | `email:{email}` | `email:{email}` → **hash** | `{ [appId]: publicKey }` (see §3.2) |
| Challenge | `challenge:{publicKey}` | `challenge:{appId}:{publicKey}` | challenge string |
| Session | `session:{token}` | `session:{appId}:{token}` | `publicKey` or `publicKey\|fp` |
| Rate limit | `ratelimit:{id}` | `ratelimit:{appId}:{id}` | counter |

A single helper centralizes the scheme so no call-site hand-concatenates:

```ts
// src/server/keys.ts (new) — one source of truth for the app-scoped keyspace.
export function appScoped(prefix: string, appId: string, id: string): string {
  return `${prefix}${appId}:${id}`; // appId is validated to exclude ':' (see §3.4)
}
```

> **Why the email index is *not* `pubKey`-namespaced the same way.** Lookups *into* a user record are always
> by `(appId, publicKey)`, so a namespaced string key is the simplest, atomically-writable choice. The email
> index instead must express *"one email, many apps"* — that is a **map**, and a map is exactly the
> `{ appId: publicKey }` value the request asks for. It also unlocks a future "link my accounts across apps"
> view for free (`HGETALL email:{email}`).

### 3.2 Email identity as a `{ appId: publicKey }` map (B — the requested shape)

`email:{email}` becomes a **Redis hash** whose fields are `appId`s and whose values are that app's identity
public key:

```
HSET    email:alice@example.com  appA  PubKeyOnAppA
HSET    email:alice@example.com  appB  PubKeyOnAppB
HGET    email:alice@example.com  appA            → PubKeyOnAppA
HGETALL email:alice@example.com                  → { appA: PubKeyOnAppA, appB: PubKeyOnAppB }
HDEL    email:alice@example.com  appA
```

This is the literal `pubkey: { appid: users_public_key, appid2: same_user_public_key }` model — one email,
a per-app public key under each `appId`.

**Why a hash and not a JSON string.** A JSON string forces read-modify-write (`HGETALL`-equivalent → parse →
add field → `SET`), which is **not atomic**: two concurrent registrations of the same email on different apps
can lose a write. A Redis hash makes each `HSET appId pubkey` an **atomic per-field** write — no lost
updates, and no need for a Lua/transaction. This requires **adding hash ops to `StorageAdapter`**:

```ts
// src/storage/adapter.ts — additive interface methods (implement in redis/kv/memory adapters)
hget(key: string, field: string): Promise<string | null>;
hset(key: string, field: string, value: string): Promise<void>;
hdel(key: string, field: string): Promise<void>;
hgetall(key: string): Promise<Record<string, string>>;
```

Upstash REST, Vercel KV, and ioredis all support `HGET/HSET/HDEL/HGETALL` natively; the in-memory test
adapter implements them over a nested `Map`. *(Fallback if we choose not to touch the adapter: keep a JSON
string and document the read-modify-write atomicity caveat — **not recommended**; see §11 Alternatives.)*

### 3.3 `UserData` gains `appId`

```ts
// src/core/types.ts — UserData
export interface UserData {
  appId: string;        // NEW — the app this record belongs to; pinned at registration
  publicKey: string;
  email?: string;
  authPublicKey?: string;
  authMethod: AuthMethod;
  wallets: EncryptedWallet[];
  createdAt: number;
  pbkdf2Iterations?: number;
  [extra: string]: unknown;
}
```

Self-describing records let an auditor assert "a record returned for `appId=X` always has `appId===X`" and
let migration/debugging tools see ownership directly.

### 3.4 `appId` validation (new, server-side)

`appId` is now attacker-influenced (it's in the request), so it must be validated **before** it touches a
key — otherwise it is a key-injection / namespace-squatting vector.

```ts
// src/server/routes.ts — alongside validatePublicKey/validateEmail
const APP_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i; // no ':' (key separator), no whitespace, bounded length
function validateAppId(appId: string, config: AuthConfig): string | null {
  if (!appId || !APP_ID_RE.test(appId)) return "Invalid appId format";
  if (config.allowedAppIds && !config.allowedAppIds.includes(appId)) return "Unknown appId";
  return null;
}
```

- **Forbid `:`** — it is the namespace separator; allowing it lets a crafted `appId` escape its namespace.
- **Allowlist (`config.allowedAppIds?: string[]`, default `undefined` = allow any well-formed id).** Set in
  production to the known set of apps so an attacker can't mint arbitrary namespaces (storage-bloat DoS) or
  probe another tenant by guessing ids.

### 3.5 Where `appId` comes from per request

| Route | Source of `appId` |
|---|---|
| `challenge`, `register`, `login`, `loginWallet`, `connectWallet` | **request body** field `appId` (required) |
| `logout`, `userData`, `importWallet`, `searchWallet` | **request header** `config.appIdHeader` (`ttc-app-id`), alongside the existing `publicKeyHeader`/`sessionHeader` |

New config: `appIdHeader: "ttc-app-id"`. When a single deployment serves exactly one app, the client may
omit it and the server falls back to `config.appId` (the existing default) for **backward-compatible
single-app deployments** — but a multi-app deployment must send it.

---

## 4. Flow changes

### 4.1 Register (`routes.ts:191-272`)

```
in:  { appId, publicKey, email?, authPublicKey?, authMethod?, wallets?, signature?, challenge?, pbkdf2Iterations? }

1. validateAppId(appId)                                   → 400 on failure (NEW)
2. validatePublicKey / validateEmail / validateAuthPublicKey / validateWallets / validIterations  (unchanged)
3. rate-limit key → ratelimit:{appId}:register:{email|publicKey}
4. exists?  getUserByPublicKey(appId, publicKey)          → 409 if found      (now app-scoped)
5. email collision (per-app ONLY):
     pk = HGET email:{email} {appId}
     if pk → 409 "Account already exists"                 (same email on OTHER apps is FINE)
6. wallet auth: verify signature, then consumeChallenge(appId, publicKey, challenge)   (now app-scoped)
7. persist:
     SET  pubKey:{appId}:{publicKey} = JSON(UserData incl. appId)
     HSET email:{email} {appId} {publicKey}               (merge into the {appId: pubKey} map)
8. issueSession(appId, user)  →  SET session:{appId}:{token} = publicKey(|fp)
```

Step 5 is the crux: registering the **same email on a new app** now **adds an entry to the map** instead of
returning 409. Re-registering the **same email on the same app** still 409s.

### 4.2 Login — email (`routes.ts:274-301`)

```
in:  { appId, email, signature, challenge }

publicKey = HGET email:{email} {appId}                    (per-app resolve; null → invalid creds)
user      = GET  pubKey:{appId}:{publicKey}
verify authPublicKey signature over challenge             (authPublicKey was derived with appId-mixed appKey — consistent)
consumeChallenge(appId, publicKey, challenge)
issueSession(appId, user)
```

### 4.3 loginWallet / connectWallet (`routes.ts:303-384`)

Both key off `pubKey:{appId}:{publicKey}` and `challenge:{appId}:{publicKey}`. This **fixes collision #1**:
the same wallet `W` now has an independent `UserData` per app, each with wallets encrypted under that app's
appKey — no cross-app decrypt failure, no backfill mixing.

### 4.4 challenge (`routes.ts:155-189`)

```
in:  { appId, publicKey? | email? }

validateAppId(appId)
rate-limit → ratelimit:{appId}:challenge:{publicKey|email}
resolve publicKey:  body.publicKey  OR  HGET email:{email} {appId}
issueChallenge(appId, publicKey)  →  SET challenge:{appId}:{publicKey} = challenge (TTL)
return { challenge, pbkdf2Iterations: GET(pubKey:{appId}:{publicKey}).pbkdf2Iterations }
```

### 4.5 Authenticated routes (`logout`, `userData`, `importWallet`, `searchWallet`)

Read `appId` from `config.appIdHeader`; `verifySession` becomes app-scoped:

```ts
// session.ts — sessionKey & verifySession now take appId
function sessionKey(appId: string, token: string, config: AuthConfig) {
  return appScoped(config.keyPrefixes.session, appId, token);
}
```

A token minted by App A keys under `session:{A}:{token}`; App B looks under `session:{B}:{token}` and finds
nothing → **fixes collision #4 (session bleed)**.

---

## 5. Signatures (function-level deltas)

| Function | Today | `0.4.0` |
|---|---|---|
| `persistUser` | `(storage, user, config)` | unchanged sig; writes `appId`-scoped key + `HSET` email map (reads `user.appId`) |
| `getUserByPublicKey` | `(storage, publicKey, config)` | `(storage, appId, publicKey, config)` |
| `resolvePublicKeyByEmail` | `(storage, email, config) → publicKey` | `(storage, appId, email, config) → publicKey` (via `HGET`) |
| `issueSession` / `verifySession` / `revokeSession` | `(…, config, …)` | add `appId` |
| `issueChallenge` / `consumeChallenge` | `(storage, publicKey, …)` | `(storage, appId, publicKey, …)` |
| `checkRateLimit` | `(storage, id, …)` | id is pre-scoped to `{appId}:{id}` by callers |

---

## 6. Config changes (`src/core/config.ts`)

```ts
export interface AuthConfig {
  // ...existing...
  appId: string;                 // now ALSO the single-app fallback when a request omits appId
  allowedAppIds?: string[];      // NEW — production allowlist; undefined = allow any well-formed id
  appIdHeader: string;           // NEW — default "ttc-app-id" (authenticated routes)
  // keyPrefixes unchanged in shape; scheme is now prefix + appId + ':' + id via appScoped()
}
```

`DEFAULT_CONFIG`: `allowedAppIds: undefined`, `appIdHeader: "ttc-app-id"`. `keyPrefixes` strings stay the
same (`pubKey:`, `email:`, …); only the *composition* gains the `appId` segment.

---

## 7. Migration — NOT SHIPPED (clean slate)

> **Decision:** existing users are **not** migrated. `0.4.0` starts fresh; old flat keys are simply orphaned.
> The script and dual-read shim below were specified but **deliberately not built**. Retained for reference
> in case a future deployment needs to preserve pre-0.4.0 data.

Existing single-DB deployments have **flat** keys. After upgrade the server reads **scoped** keys, so without
migration every existing user appears unregistered.

### 7.1 Migration script — `scripts/migrate-0.4.0.mjs`

Given the deployment's current `appId` (the value it has been running with, default `"ttc"`):

```
for each  pubKey:{publicKey}:
    record = GET pubKey:{publicKey}
    record.appId = APP_ID
    SET  pubKey:{APP_ID}:{publicKey} = JSON(record)
    DEL  pubKey:{publicKey}

for each  email:{email}  (old string value = publicKey):
    pk = GET email:{email}
    HSET email:{email} {APP_ID} {pk}          # string → hash, preserving the value
    # (old string is replaced by the hash at the same key)

# challenge:* are short-TTL (300s) and session:* are 4h — OPTIONALLY left to expire,
# or rewritten to challenge:{APP_ID}:* / session:{APP_ID}:* if zero-downtime cutover is required.
```

The script must be **idempotent** (safe to re-run) and **dry-run-first** (`--dry-run` prints the rewrite
plan and counts before mutating). It needs the Upstash REST creds already present in the Vercel env.

### 7.2 Transition options

- **Maintenance-window cutover (simplest):** run `migrate-0.4.0.mjs`, deploy `0.4.0`. Short-TTL keys
  (challenge/session) drained by waiting out their TTL or migrated explicitly.
- **Dual-read shim (optional, zero-downtime):** behind `config.legacyKeyFallback: boolean` (default
  `false`), `getUserByPublicKey` falls back to the flat `pubKey:{publicKey}` on a scoped miss and lazily
  re-writes it scoped. Remove the shim in `0.5.0`. Documented as a deliberate, time-boxed compatibility cost.

---

## 8. Backward compatibility & breaking-change summary

| Area | Change | Breaking? |
|---|---|---|
| Request contract | `appId` required in body (`challenge`/`register`/`login`/`loginWallet`/`connectWallet`) and header for authed routes | **Yes** |
| Redis key scheme | `pubKey:`/`challenge:`/`session:`/`ratelimit:` gain `{appId}:` segment | **Yes** (migration) |
| Email index | `email:{email}` string → hash `{ appId: publicKey }` | **Yes** (migration) |
| `UserData` | new `appId` field | Additive (but persisted) |
| `StorageAdapter` | new `hget/hset/hdel/hgetall` | Additive (interface grows) |
| Client SDK | must send `appId` (it already knows it — it's in client config) | **Yes** (minor — value already on hand) |
| Single-app deploy | header/body `appId` may be omitted → falls back to `config.appId` | Non-breaking path preserved |

Client impact is small: the client **already** holds `appId` (it derives keys with it), so sending it is a
one-line addition per request, not new state.

---

## 9. Security model & required new audit (§ explicitly requested)

This refactor **moves a tenant boundary into the storage layer**, so it requires a **fresh audit**. Audit
scope:

1. **Cross-app isolation (the core invariant).** Prove no key read/written for `appId=X` can ever resolve a
   record owned by `appId=Y`. Assert `UserData.appId === requestAppId` on every read path. Fuzz `appId` to
   attempt namespace escape (`:`, `*`, unicode, overlong, empty).
2. **`appId` injection / squatting.** `validateAppId` + `allowedAppIds`: confirm a crafted `appId` cannot
   inject a `:` to cross namespaces, and that without an allowlist an attacker can still only create
   well-formed namespaces (storage-bloat DoS bound — recommend allowlist in prod).
3. **Email-map privacy & atomicity.** `HGETALL email:{email}` reveals *which apps a given email uses* — a
   cross-app correlation oracle. Confirm it is never returned to clients (it is server-internal). Verify
   concurrent same-email registrations on different apps don't lose a field (atomic `HSET`).
4. **Session scoping.** A token from App A must be rejected by App B (no `session:` bleed). Re-verify the
   UA-binding logic (`session-ua-binding-0.3.2`) composes with the new `appId` segment.
5. **Challenge scoping.** App A's challenge for wallet `W` must not satisfy App B (no `challenge:` clobber);
   single-use `getdel` semantics preserved per app.
6. **Rate-limit scoping.** Buckets are now `{appId}:{id}`. Confirm one app can't exhaust another's buckets,
   **and** that the H5 "global `unknown` lockout" mitigation still holds within each app namespace.
7. **Re-validate prior findings under the new dimension:** F2/SERVERSIDE-11 (Solana `publicKey` validation,
   `routes.ts:48-62`) unchanged but now paired with `appId`; F3 (PBKDF2 bounds); WI-5 (verify-before-consume
   so a forged sig can't burn a challenge) — re-check per app.
8. **Migration correctness.** No record dropped, mis-scoped, or double-counted; idempotent re-run; string→hash
   email conversion lossless.

Deliverable: a new `audits/v0.4.0-PRD.md` enumerating findings, mirroring the existing audit docs.

---

## 10. Testing (new scripts required)

### 10.1 New Jest suites

- **`tests/multi-app.test.ts`** — the headline behaviors:
  - Same email registers independently on `appA` and `appB` → **no false 409**; two records; `email:{email}`
    hash has both fields.
  - Email login with the wrong `appId` → `Invalid credentials` (resolves `null`).
  - Same wallet `connect` on `appA` then `appB` → two independent `UserData`, each with its own
    `wallets[]`; App B does **not** see App A's bundle (fixes collision #1).
  - Challenge issued under `appA` does **not** satisfy `appB` (fixes #3).
  - Session minted under `appA` rejected by `userData`/`logout` under `appB` (fixes #4).
  - `validateAppId`: reject `:`-bearing, empty, overlong, and (with `allowedAppIds` set) unknown ids.
- **`tests/storage-hash.test.ts`** — `hget/hset/hdel/hgetall` across `MemoryAdapter` and the KV/Upstash
  adapter coercion (parallels `tests/storage-kv.test.ts`).
- **`tests/migrate-0.4.0.test.ts`** — seed flat keys → run migration in-process → assert scoped keys + hash
  email map; assert idempotent re-run; assert `--dry-run` mutates nothing.

### 10.2 New smoke script (parallels `smoke:biometric`)

`scripts/smoke-multi-app.mjs` + `package.json` script **`smoke:multiapp`**
(`"smoke:multiapp": "npm run build && node scripts/smoke-multi-app.mjs"`), mirroring the existing
`smoke:biometric` entry. No network: drives `createAuthHandlers` over `MemoryAdapter`, registers the same
email under two `appId`s, and asserts isolation end-to-end. Keeps a runnable, dependency-free demonstration
of the breaking change for reviewers.

> Project rule honored across all of the above: tests use only ephemeral/synthetic keys (matching
> `tests/_auth-helpers.ts` and `scripts/smoke-biometric.mjs`).

---

## 11. Alternatives considered

- **`pubKey:{appId}:{publicKey}` namespacing only, keep `email:` as a string with `appId` baked in
  (`email:{appId}:{email}`).** Simplest and fully isolates apps, but does **not** produce the requested
  `{ appId: publicKey }` map and gives no "one email across apps" view. Rejected in favor of the hash, which
  satisfies the explicit request and is atomic.
- **Email map as a JSON string** instead of a Redis hash. Avoids touching `StorageAdapter`, but read-modify-
  write is non-atomic (lost updates on concurrent cross-app same-email registration). Acceptable only as a
  fallback; the hash is preferred.
- **Separate Upstash DB per app.** The status quo "solution" this PRD exists to avoid — defeats the goal of
  one DB on one Vercel project.
- **`appId` from a trusted header only (never body).** Cleaner trust story, but the unauthenticated
  `register`/`challenge` flows have no session to bind a header to, and the client already controls `appId`
  regardless — so validation + allowlist is the real control, not header-vs-body.

---

## 12. Files to touch

| File | Change |
|---|---|
| `src/core/config.ts` | `allowedAppIds`, `appIdHeader`; `appScoped` composition; defaults |
| `src/core/types.ts` | `UserData.appId` |
| `src/server/keys.ts` *(new)* | `appScoped(prefix, appId, id)` helper |
| `src/server/session.ts` | `appId` in `persistUser`/`get…`/`resolve…`/`issue/verify/revokeSession`; email `HSET`/`HGET` |
| `src/server/challenge.ts` | `appId` in `issueChallenge`/`consumeChallenge` |
| `src/server/rateLimit.ts` | callers pass `{appId}:{id}` identifiers |
| `src/server/routes.ts` | `validateAppId`; read `appId` (body + `appIdHeader`); thread through all 9 handlers |
| `src/storage/adapter.ts` | `hget/hset/hdel/hgetall` |
| `src/storage/{redis,kv,memory}.ts` | implement hash ops |
| `src/client/*`, `src/react/*`, `src/next/*` | send `appId` (body + header) |
| `scripts/migrate-0.4.0.mjs` *(new)* | flat → scoped migration (idempotent, `--dry-run`) |
| `scripts/smoke-multi-app.mjs` *(new)* + `package.json` | `smoke:multiapp` |
| `tests/multi-app.test.ts`, `tests/storage-hash.test.ts`, `tests/migrate-0.4.0.test.ts` *(new)* | coverage |
| `audits/v0.4.0-PRD.md` *(new)* | fresh audit (§9) |
| `README.md`, `docs/CRYPTO_SPEC.md`, `docs/THREAT_MODEL.md` | document multi-app model + breaking change |

---

## 13. Non-goals

- **Not** changing client-side key derivation — `appId` already salts it; this PRD only adds the **server**
  dimension.
- **Not** a cross-app SSO / shared-session feature. Sessions are deliberately app-scoped (isolation, not
  sharing). A future "link accounts across apps" view can read the email map, but that is out of scope here.
- **No** per-app config overrides on one deployment (rate limits, TTLs stay global). Can follow later.
- **Not** auto-migrating without operator action — migration is an explicit, audited step.

---

## 14. Decisions (resolved — as built)

1. **Email map representation:** ✅ Redis **hash** (`hset/hget/hgetall` added to `StorageAdapter` and all
   adapters) — atomic per-field, no lost updates.
2. **`allowedAppIds` default:** ✅ `undefined` (allow any well-formed appId) for DX; production deployments
   are advised to set it. Enforced by `validateAppId`.
3. **Migration style:** ✅ **None** — clean slate, per product decision (see §7).
4. **Single-app fallback:** ✅ Kept — a request that omits `appId` falls back to `config.appId` (default
   `"ttc"`), so single-app deployments are unchanged in behavior (keys are now `…:ttc:…`).

---

## 15. Acceptance criteria

- [x] `appId` is validated on `challenge`/`register`/`login`/`loginWallet`/`connectWallet` (body) and
      authenticated routes (`appIdHeader`); `:`/empty/overlong/unknown rejected. *(Optional with
      `config.appId` fallback, not strictly required — see §14.4.)*
- [x] Redis keys are `appId`-scoped for `pubKey`/`challenge`/`session`/`ratelimit`; `email:{email}` is a
      `{ appId: publicKey }` hash.
- [x] Same email registers independently on two apps (no false 409); each app resolves only its own record.
- [x] Same wallet yields independent per-app `UserData`; no cross-app bundle mixing; no session/challenge bleed.
- [x] ~~Migration script~~ — **intentionally not shipped** (clean slate, §7).
- [x] New suites (`multi-app`, `storage-hash`) + `smoke:multiapp` green; existing suite green (267 total).
- [ ] **TODO (owner: security):** fresh audit `audits/v0.4.0-PRD.md`; prior findings (F2/SERVERSIDE-11, F3,
      H5, WI-5, UA-binding) re-validated under the `appId` dimension.
- [x] `format:check` + `typecheck` + `test` + `build` green.

### Implementation map (as built)

| Concern | File(s) |
|---|---|
| `appId` namespace helper | `src/server/keys.ts` (`appScoped`) |
| `UserData.appId` | `src/core/types.ts` |
| `allowedAppIds`, `appIdHeader` | `src/core/config.ts` |
| Hash ops (`hget/hset/hdel/hgetall`) | `src/storage/{adapter,memory,redis,kv}.ts` |
| App-scoped pubKey/email-hash/session | `src/server/session.ts` |
| App-scoped challenge | `src/server/challenge.ts` |
| `validateAppId` + threading through 9 handlers | `src/server/routes.ts` |
| Client sends `appId` (body + `appIdHeader`) | `src/client/authClient.ts` |
| Tests | `tests/multi-app.test.ts`, `tests/storage-hash.test.ts` (+ updated existing) |
| Smoke | `scripts/smoke-multi-app.mjs`, `package.json` `smoke:multiapp` |
