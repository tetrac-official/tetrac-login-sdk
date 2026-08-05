---
name: multi-database
description: Back `@tetrac/login-sdk` with a database, or debug one. Postgres/Supabase, MySQL, and SQLite are SHIPPED (v0.6.0, `@tetrac/login-sdk/storage/sql`) — do NOT hand-write those; use `createPostgresAuthStore` / `createMysqlAuthStore` / `createSqliteAuthStore` and the generated schema. Redis/Upstash ship as `StorageAdapter`. Only a NEW engine class (Mongo, DynamoDB, Convex, Durable Objects) needs a hand-written `AuthStore`, and this skill encodes the correctness contract it must honor: expiry-on-read, the permanent-rate-limit-lockout bug, atomic get-and-delete (challenge replay), no-lost-write on the email index, normalizeEmail (never a case-insensitive collation), injection safety, fail-closed errors — plus how to run the shipped conformance suite against a real engine. Use when — choosing a database for the SDK; wiring Postgres/Supabase/MySQL/SQLite/Mongo/DynamoDB/Convex behind it; adding a SQL dialect; running the conformance suite or the Docker engine tests; or debugging "user permanently rate-limited", "session accepted after it expired", "challenge replayed", "email index lost a write", "two accounts collided", "locked out of their wallets", "Supabase table is world-readable", "preflight refuses to boot", "Convex write conflict / OCC". Triggers — "add a database", "Postgres adapter", "Supabase auth store", "MySQL backend", "SQL dialect", "Convex backend", "custom AuthStore", "hitRateLimit", "bring my own database", "multi-db", "storage conformance", "test:docker".
---

# Backing `@tetrac/login-sdk` with a database

## 🛑 STOP — for Postgres, MySQL, and SQLite, there is nothing to implement

These are **shipped** (v0.6.0). Do not hand-write an `AuthStore` for them. Do not hand-write the
schema. Both are load-bearing and both are already correct:

```ts
import { createPostgresAuthStore, schemaFor } from "@tetrac/login-sdk/storage/sql";

// 1. schemaFor("postgres" | "mysql" | "sqlite")  → run it against your DB
// 2. point the SDK at it. Preflight runs here and REFUSES TO BOOT on the dangerous stuff.
const store = await createPostgresAuthStore({ client: pool });
export const { GET, POST } = createNextAuthRoutes({ store });
```

`createPostgresAuthStore` covers **Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly, and
CockroachDB** — one Postgres wire protocol. `createMysqlAuthStore` and `createSqliteAuthStore` are
the same shape. Redis/Upstash stay on `{ storage }` and are unchanged.

**Why the hard stop:** every hazard in this document *used to be* the integrator's problem. Under
[ADR-002](../../../PRD/ADR-002-uniform-backend-architecture.md) the SDK owns them — one engine
(`SqlAuthStore`) plus a ~30-line dialect per database. Hand-writing a Postgres backend today means
re-deriving eight correctness rules that are already written, tested against real engines, and
fixed. **You would be reintroducing solved bugs.**

## So when do I actually implement something?

| You want… | Do this |
|---|---|
| Postgres / Supabase / Neon / RDS / CockroachDB | `createPostgresAuthStore` — **nothing to write** |
| MySQL / MariaDB | `createMysqlAuthStore` — **nothing to write** |
| SQLite / libSQL / Turso | `createSqliteAuthStore` — **nothing to write** |
| Redis / Upstash / Vercel KV | `{ storage }` — **nothing to write** |
| **Another SQL engine** (e.g. Oracle, MSSQL) | A **`SqlDialect`** — ~30 lines. See *Adding a SQL dialect*. |
| **A non-SQL engine** (Mongo, DynamoDB, Firestore, Convex, Durable Objects) | A hand-written **`AuthStore`**. This is the only case where the eight hazards below are yours. |

**Companion docs:** [`docs/DATABASES.md`](../../../docs/DATABASES.md) (which database, and why —
including the ones that **cannot** work); [`PRD/ADR-002`](../../../PRD/ADR-002-uniform-backend-architecture.md)
(why the SDK owns the correctness); [`docs/STORAGE_ADAPTERS.md`](../../../docs/STORAGE_ADAPTERS.md)
(the `AuthStore` contract). The invariants also live in the interfaces themselves —
`src/storage/store.ts`, `src/storage/adapter.ts`, `src/storage/sql/types.ts`.

## The two ports (only relevant if the table above sent you here)

| Port | What it is | Implement it when |
|---|---|---|
| **`AuthStore`** (`src/storage/store.ts`) | The **domain** port: `getUser`, `putUser`, `getPublicKeyByEmail`, `putChallenge`, `takeChallenge`, `putSession`, `getSession`, `deleteSession`, **`hitRateLimit`**, + optional `sweepExpired`/`close`. | A **non-SQL** engine the SDK doesn't ship. |
| **`StorageAdapter`** (`src/storage/adapter.ts`) | The **KV** port: 10 Redis-shaped primitives. `KvAuthStore` wraps any of these into an `AuthStore`. | Only a genuine Redis-style store with native atomic `INCR`, TTL, and `GETDEL`. |

**Why `AuthStore` and not the KV port** ([ADR-001](../../../PRD/ADR-001-storage-seam.md)):
`StorageAdapter` is named for what it *is* (a key-value store), not what it is *for* (auth state),
so every backend must **emulate Redis**. The clearest proof is `incr`:

> A rate-limit counter is *many writes to one row*. On **Convex** that is the *documented
> anti-pattern* — OCC write conflicts, and the mutation eventually **throws** under exactly the burst
> traffic a rate limiter exists to survive. The fix is a **sharded** counter. But `incr(key)` is a
> *primitive*, not a *decision* — so the KV port **forbids the only correct implementation.**
> `hitRateLimit(bucket, window, max)` allows it, invisibly.

**Consequence: several hazards below are artifacts of the KV port, not of the problem.** Hazards
**1, 5, 6** (permanent lockout, collation, key sizing) largely evaporate under `AuthStore` — you
store typed fields instead of emulating Redis over concatenated strings. Hazards **2, 3, 7, 8**
(expiry-on-read, atomic get-and-delete, injection, email normalization) **survive both ports**.
Those are the real ones.

## The one rule for the KV port

> **A key is an opaque, attacker-influenced byte string. Store it; never parse, split, interpret,
> truncate, case-fold, or path-split it.**

Keys are assembled by `appScoped()` (`src/server/keys.ts`) and embed base58 public keys, hex tokens,
email addresses, and a tenant `appId` that may come straight off the request. The `appId` is
validated upstream to exclude `':'`, so namespace escape is already handled — **an adapter must not
add validation, and must not add interpretation.** (Under `AuthStore` this rule mostly evaporates:
`appId` and `publicKey` are *typed arguments*, not substrings of a synthetic key.)

---

## The eight ways a backend goes wrong

### 1. `incr` on an expired key → permanent rate-limit lockout 🚨

> **KV port only.** Under `AuthStore` this bug is **unrepresentable** — `hitRateLimit()` is one
> atomic call returning a decision, so there is no two-step dance to get wrong. This hazard is the
> single strongest argument for the domain port.

The single nastiest bug in this space. `checkRateLimit` infers "first hit of a new window" from
`count === 1`, and only *then* stamps the TTL (`src/server/rateLimit.ts`). The obvious SQL upsert —
`INSERT … ON CONFLICT (key) DO UPDATE SET value = value + 1 RETURNING value` — against a stale,
long-expired row returns `16`, not `1`. The TTL is never stamped, the self-heal branch re-`expire`s
the row, and that identifier — an **IP, an email, or a public key** — is rate-limited **forever**.
It will not show up in any smoke test: it only manifests after a window elapses under traffic.

The invariants, written out:

- **(a)** An expired key is **indistinguishable from an absent key**, on every read path.
- **(b)** `incr` on an expired key returns **`1`** — fresh counter, stale TTL dropped.
- **(c)** `incr` on a **live** key **preserves its existing TTL** — never extends, never clears.
- **(d)** `expire` on an absent/expired key is a **no-op** — it must never create or resurrect a row.

Fold the expiry check into the upsert. One statement, engine-enforced atomicity, no
read-modify-write:

```sql
INSERT INTO ttc_kv (key, value, expires_at) VALUES ($1, '1', NULL)
ON CONFLICT (key) DO UPDATE SET
  value = CASE WHEN ttc_kv.expires_at IS NOT NULL AND ttc_kv.expires_at <= $2
               THEN '1' ELSE (ttc_kv.value::bigint + 1)::text END,   -- (b) / (c)
  expires_at = CASE WHEN ttc_kv.expires_at IS NOT NULL AND ttc_kv.expires_at <= $2
                    THEN NULL ELSE ttc_kv.expires_at END             -- drop stale TTL, keep live TTL
RETURNING value;
```

`MemoryAdapter.incr` does exactly this via `alive()`, which self-deletes the expired entry first.
**`MemoryAdapter` is the normative reference implementation** — when this skill and `MemoryAdapter`
disagree, `MemoryAdapter` is right. And that is no longer a claim: the conformance suite runs against
a **live Redis** in CI, so "MemoryAdapter matches Redis" is a *tested fact* rather than a comment.

### 2. Expiry must be enforced **on read**, never by a background reaper 🚨

> **Survives BOTH ports. This is the one hazard you can never design away** — `getSession` and
> `takeChallenge` must return `null` for an expired value even if no sweeper has ever run.

`consumeChallenge` accepts any non-null value `getdel` returns; `verifySession` accepts any non-null
value `get` returns. **Neither performs an independent expiry check** — both delegate expiry
entirely to the storage layer. That is fine against Redis, whose expiry is exact.

It is **not** fine against a background sweep. MongoDB's TTL index is swept **roughly every 60
seconds**, best-effort under load. A session bearer token or a challenge therefore stays **readable
and accepted for up to a minute past its TTL**. Same for any `pg_cron`/reaper design.

> Every adapter filters on expiry **in the read path itself** — `WHERE expires_at IS NULL OR
> expires_at > $now`, or the Mongo filter equivalent. A TTL index or reaper is **space reclamation
> only** and is never the expiry authority. Mongo adapters MUST store an explicit `expiresAt` and
> filter on it, *in addition to* the TTL index.

And the flip side: **lazy expiry alone leaks storage.** Rate-limit rows, abandoned challenges, and
expired sessions are typically never read again, so they are never lazily deleted. Redis reclaims
automatically; SQL does not. Implement the optional `sweepExpired?(limit?)` for space, wire it to
`pg_cron` / a cron route, and remember those dead rows contain **PII** (rate-limit keys embed emails
and IPs) — it is a data-retention obligation, not just disk.

### 3. `getdel` must be atomic → or challenges become replayable 🚨

`getdel` is the **sole** mechanism closing the challenge-replay race (`src/server/challenge.ts`).
Two concurrent consumes must never both observe the value.

- **Postgres / SQLite ≥3.35:** `DELETE … WHERE key = $1 AND (expires_at IS NULL OR expires_at > $2) RETURNING value` — one statement.
- **MySQL: has no `DELETE … RETURNING`.** It needs an explicit transaction (`SELECT … FOR UPDATE`,
  then `DELETE`). Getting this wrong turns a single-use challenge into a replayable one. This is why
  MySQL is the *last* backend to ship, not the first.
- Conformance case: fire N concurrent `getdel`s; **exactly one** observes the value.

### 4. `hset` must be per-field atomic → or registrations lose writes

The email→`{appId: publicKey}` index is a **hash** specifically so two concurrent registrations of
the same email under different `appId`s cannot lose a write. An adapter that stores the hash as one
JSON blob and does `SELECT → merge → UPDATE` **reintroduces exactly the race the hash was built to
eliminate.**

Give the hash its own table, keyed `(key, field)`, and make `hset` a single upsert. **The hash table
has no `expires_at`** — the email index is permanent by design. Do not add a TTL to it.

**Mongo trap 🚨 — do NOT model the hash as subdocument fields.** The natural
`$set: {["fields." + field]: value}` is **broken by the SDK's own recommended config**: the hash
field is an `appId`, `APP_ID_RE` permits `.`, and the documented recommended value is a domain like
`"myapp.example"`. Mongo reads `.` in an update path as **nesting**, so tenants `myapp` and
`myapp.example` collide — one silently destroys the other's index entry, or `hset` hard-errors and
registration fails. Use a **separate collection** with a compound unique index on `{key, field}`,
passing `key`/`field` as scalar values:

```js
await hash.updateOne({ key, field }, { $set: { value } }, { upsert: true });   // hset
```

### 5. Collation must be **binary and non-padding** → or accounts and tenants collide 🚨

> **Mostly KV-port.** Under `AuthStore`, `appId` and `publicKey` are typed columns — but a
> **case-insensitive collation still collides `Acme`/`acme` as tenants and `K`/`k` as users**, so
> the binary-collation requirement survives on MySQL either way. What *goes away* is the synthetic
> concatenated key.

Keys embed **case-sensitive** base58 and hex. MySQL's default (`utf8mb4_0900_ai_ci`) is
case-**insensitive** — two distinct Solana addresses differing only in case map to the **same
primary-key row**, and tenants `Acme` and `acme` become the **same namespace**. Cross-account and
cross-tenant corruption, from a default nobody thinks to override.

**Binary is necessary but not sufficient on MySQL.** `utf8mb4_bin` is **`PAD SPACE`**: it compares
ignoring trailing spaces, so `'k'` and `'k '` are *equal*, including for primary-key uniqueness.

- **MySQL:** use **`VARBINARY(512)`** (byte-wise, no padding) — or `utf8mb4_0900_bin` (NO PAD,
  MySQL ≥8.0.1). **Never `utf8mb4_bin`.**
- **Postgres:** correct by default (deterministic `C` collation). Reject a database created with a
  **nondeterministic ICU collation**.
- **SQLite:** correct by default (`BINARY`). Never declare a column `COLLATE NOCASE`.
- Conformance: `set("K")`/`set("k")` are independent, **and** `set("k")`/`set("k ")` are independent.

### 6. Column sizing → silent truncation is an unrecoverable account 🚨

- **Keys:** worst case is a rate-limit key built from an email — `ratelimit:` + `register:` +
  `appId` (≤64) + `:` + email (**≤320**, per `validateEmail` — not the 254 of RFC folklore) =
  **~404 bytes**. **Size keys at 512.** Do not "optimize" to 384.
- **Values:** a `UserData` blob holds up to `maxWalletsPerUser` = **64** encrypted wallets ≈ **15 KB**.
  MySQL `TEXT` caps at 65,535 bytes and, **in non-strict mode, truncates silently rather than
  erroring**. A truncated blob is invalid JSON → `getUserByPublicKey`'s `JSON.parse` throws → its
  `catch` returns `null`. The record fails *safe*, but the user is **permanently locked out of every
  wallet in it**, with nothing anywhere pointing at the database. Use **`MEDIUMTEXT`** and assert
  **`STRICT_ALL_TABLES`**.
- **Over-length keys: reject (throw), never truncate.** A truncating write silently merges two
  distinct keys into one row.

### 7. Injection safety — and NoSQL injection is *structural*, not lexical

Keys and values carry attacker-influenced substrings (emails, public keys, a request-supplied
`appId`). **No adapter may interpolate a key, field, or value into a query string.**

- **SQL:** parameterized queries, exclusively. No exceptions, not even for the table name.
- **Mongo:** there is no query string to escape, so the classic defense doesn't apply and the bug
  looks like ordinary code. Pass `key`/`field` only as **scalar string values** in a filter —
  `{ key, field }`. Never as a filter *object* (an attacker-supplied `{"$gt": ""}` becomes an
  **operator** and matches every row), never as a **key** of an update document, never near `$where`
  / `$expr`, and **never built into an update path** (see hazard 4). Assert `typeof key === "string"`
  at the boundary.
- Conformance feeds `' OR 1=1 --`, `{"$gt":""}`, `{"$ne":null}`, and `$`/`.`-containing keys through
  **every** method and asserts they round-trip as inert data.

### 8. Email matching goes through `normalizeEmail()` — NEVER through a collation 🚨

> **Survives BOTH ports.** It is a required conformance case, and it is the one hazard whose "obvious"
> fix creates a *worse* bug than the one it solves.

`A@B.com` and `a@b.com` must be the same account on every backend. The SDK exports the function that
decides this, and every `AuthStore` MUST route **both** the email-index write (`putUser`) and the read
(`getPublicKeyByEmail`) through it:

```ts
import { normalizeEmail } from "@tetrac/login-sdk/storage";   // lowercase + trim
```

The tempting shortcut is to skip it and let a **case-insensitive column collation** do the work. On
MySQL that is a disaster, because the collation does not only apply to the email: it *also* case-folds
the **`appId`** and the **base58 public key** in the same table. Tenants `Acme` and `acme` merge into
one namespace, and two distinct Solana addresses differing only in case merge into one row (hazard 5).

> **Case-insensitivity is a property of the EMAIL, not of the keyspace.** Normalize the value in code;
> keep the storage byte-exact.

---

## Errors must fail **closed**

`checkRateLimit` has no `try`/`catch`: if the store throws, the request 500s. That is **correct** — a
rate limiter that cannot count must not grant permission.

Pooled SQL clients fail in ways an in-process Redis client mostly doesn't (pool exhaustion,
connection reset, failover), so the reflex is a `catch` returning a benign default. **Every one of
those is a security control silently switching off:**

| Swallowed error | What actually happens |
|---|---|
| `hitRateLimit` returns `{allowed: true}` (or `incr` → `0`/`1`) on failure | **rate limiting is disabled** — under exactly the load that broke it |
| `putSession` / `set` swallows a write failure | a token is issued that was never stored ⇒ every later request 401s |
| `getUser` / `getSession` / `get` return `null` on failure | "the backend is down" becomes indistinguishable from "no such user / no such session" |

> **Backends propagate storage errors.** `null` means *"the backend answered, and it is absent"* —
> **never** *"the backend did not answer."* Bounded retries for transient connection errors are fine;
> converting an error into a value is not.

**This is deliberately NOT a conformance case**, and it is worth knowing why: you cannot inject a
fault into an arbitrary conforming store handed to you as a black box. It is enforced instead by a
*caller-side* test in the SDK (a `BrokenRateLimitStore` whose `hitRateLimit` throws, asserting the
route rejects rather than allows). A green conformance run says nothing about this — so review it by
hand, every time.

---

## Deployment hazards — now mostly CHECKED, not documented

> **Preflight runs at construction and REFUSES TO BOOT** on the ones that fail silently and
> catastrophically. Prose never stopped these; a failed deploy does. For the shipped SQL backends
> you get this for free:
>
> | Check | Level |
> |---|---|
> | Tables in Supabase's world-readable **`public` schema** | 🚨 **error — refuses to boot** |
> | **MySQL not in strict mode** (silent truncation ⇒ user loses every wallet) | 🚨 **error** |
> | MySQL key columns not **binary** (would merge tenants and accounts) | 🚨 **error** |
> | Schema not created | 🚨 **error** |
> | **SQLite file under a web-served directory** (`public/auth.db`) | 🚨 **error** |
> | SQLite file world-readable; nondeterministic Postgres collation | ⚠️ warn |
>
> A hand-written `AuthStore` gets none of this. Implement `preflight()` if you write one.

The rest below is still yours — the SDK cannot audit your VPC:

- **Supabase 🚨** — Supabase auto-generates a **PostgREST API over every table in the `public`
  schema**, served to anyone holding the browser-shipped `anon` key. A table created the obvious way
  with no RLS is **world-readable**, and it contains session records and encrypted wallet blobs. This
  is the highest-severity failure mode in the whole design, it is reachable by the *most natural*
  setup path, and it is **invisible from the application side** — everything works perfectly. Create
  the tables in a **dedicated non-`public` schema**, `REVOKE` from `anon`/`authenticated`, and enable
  RLS anyway.
- **RLS that actually bites.** A table **owner bypasses RLS** unless `FORCE ROW LEVEL SECURITY` is
  set — so "enable RLS, connect as owner/`service_role`" protects nobody. Connect as a **dedicated
  DML-only role** (`SELECT/INSERT/UPDATE/DELETE` on the two tables, no DDL, no other schema) with an
  explicit policy for that role. Never use `service_role` as the SDK's connection identity: it is a
  **global admin bypass over the entire database**.
- **TLS: `sslmode=require` does NOT verify the certificate** — it encrypts and accepts *any* cert, so
  it stops passive sniffing and does nothing against an active MITM. Use **`sslmode=verify-full`**.
  Mongo: `tls=true`, and never `tlsAllowInvalidCertificates`.
- **The database's own logs are an exfiltration channel.** MySQL's general/slow query log records
  statements **with literal values**; MongoDB's profiler and slow-op lines record the **query
  filter** — which *is* the session key. Postgres logs bind params on error. Disable parameter
  logging in the driver; and note the SDK stores session tokens as **SHA-256 digests** (v0.5.0)
  specifically because you cannot control the operator's managed-DB telemetry.
- **SQLite is dev / self-host / single-instance only.** A file cannot be shared across serverless
  instances. `better-sqlite3` is **synchronous** — it blocks the event loop. And the file is a
  credential store: **mode `0600`**, **never under a web-served directory** (`public/ttc.sqlite` is a
  one-request download of the entire auth store), and the `-wal`/`-shm` sidecars need the same
  treatment.
- **Serverless pooling.** A `new pg.Pool()` per request exhausts the connection limit under
  concurrency, and the failure is a hard outage, not degradation. Use a **module-level singleton**,
  or a serverless-native driver (`@neondatabase/serverless`, `@vercel/postgres`) on edge runtimes.

---

## Choosing a backend — what works, and what cannot

The contract is the gate: the SDK needs **atomic `incr`** (rate limiting), **expiry**, **atomic
get-and-delete** (single-use challenges), and **per-field atomic hash writes**. A store missing any
of those cannot back the SDK safely, no matter how popular it is.

| Backend | `incr` | TTL | `getdel` | Verdict |
|---|---|---|---|---|
| **PostgreSQL** (→ Supabase, Neon, RDS, Railway, Render, Fly, **CockroachDB**) | ✅ | ❌ none | ✅ `DELETE…RETURNING` | **Best fit.** One adapter covers all of these — they share the Postgres wire protocol. |
| **MongoDB / Atlas** | ✅ `$inc` | ⚠️ ~60s sweep | ✅ `findOneAndDelete` | Good — with the read-path filter and the separate hash collection. |
| **SQLite / libSQL (Turso)** | ✅ | ❌ none | ✅ (≥3.35) | Good. Dev / self-host / single-instance only. |
| **DynamoDB** | ✅ atomic counters | ⚠️ **"within a few days"** | ✅ `ReturnValues=ALL_OLD` | Good — cleaner than its mindshare suggests. |
| **MySQL / MariaDB** | ✅ | ❌ | ⚠️ **no `DELETE…RETURNING`** | Workable, hardest. Needs an explicit transaction for `getdel`. Ship last. |
| **Cloudflare Durable Objects** | ✅ | ❌ (alarms) | ✅ | The **correct** Cloudflare answer — strongly consistent + transactional. |
| **Convex** | ⚠️ **sharded only** | ❌ **none** | ✅ | `AuthStore` **only**, and it ships as a **Convex component**, not an adapter. See below. |
| **Cloudflare Workers KV** | ❌ | ✅ | ❌ | 🚫 **Disqualified — cannot back this SDK.** |
| **ClickHouse / BigQuery / Snowflake / Databricks** | ❌ | — | ❌ | 🚫 Wrong engine class (OLAP). |

### Convex — the special case that proved the seam

Convex is an excellent engine (serializable mutations make atomic `takeChallenge` free, and a
component's writes commit **transactionally with the customer's own mutation** — stronger than Redis
or Postgres). But it breaks three assumptions, and every one is structural:

- **No external DB access, ever.** All reads/writes go through functions deployed in the
  **customer's** `convex/` directory; `ctx.db` does not exist outside Convex's runtime. So a Convex
  backend is **not** a driver wrapper — it ships as a **Convex component** (an npm package with its
  own private tables, functions, and cron, installed via `app.use(tetrac)` in the customer's
  `convex.config.ts`). This is a supported, well-trodden pattern — `@convex-dev/better-auth` and
  friends do it.
- **A hot counter is Convex's own documented anti-pattern.** OCC write conflicts; the mutation
  *throws* once calls arrive faster than it can execute, and the retry count is **undocumented**.
  Rate-limit counters **must be sharded** (copy or delegate to `@convex-dev/rate-limiter`:
  power-of-two-choices, lazy `(value, ts)` window recompute). This is only expressible via
  `hitRateLimit()` — never via `incr()`.
- **No document TTL at all** (zero matches in the entire docs corpus). Use `ctx.scheduler.runAfter`
  (atomic with the enclosing mutation) or an in-component cron — **plus expiry-on-read**, always.

Two traps to avoid: OCC conflicts appear to be **document-granular**, so two writes to different
*fields* of one document still contend (⇒ **one document per (email, appId)**, never a field-per-
tenant map); and a long key **cannot be a Convex field name** (64-char cap) — only a value.

**Two hard stops, and they are the two things people actually try:**

- **Cloudflare Workers KV is disqualified. 🚫** No atomic increment, no atomic get-and-delete, up to
  **60s** global propagation, and a hard cap of **1 write/sec/key**. Rate limiting would silently not
  work and challenges would be **replayable** off a stale read. It is the first thing an edge-first
  developer reaches for. Redirect them to **Durable Objects**.
- **"Native TTL" is a trap, not a feature. 🚨** On **MongoDB** (~60s), **DynamoDB** ("within a few
  days"), and **Firestore** (24h — Google's own docs say *expired documents continue to appear in
  queries*), TTL is **space reclamation, not an expiry authority**. Since `verifySession` accepts any
  non-null value `get` returns, a naïve adapter on any of these **accepts expired session tokens**.
  This is hazard 2, and it is the single most important line to hold.

Note also: **Vercel KV is a sunset product** (deprecated Oct 2024, now a Marketplace redirect to
Upstash). The `VercelKVAdapter` still works, but point new deployments at **Upstash**.

---

## Adding a SQL dialect — ~30 lines, and you cannot break the security properties

A new SQL engine (Oracle, MSSQL, …) is a `SqlDialect`. It declares only what genuinely differs
between engines. **It contains no auth logic at all**, which is the point: a dialect author never
writes a rate limiter, so a dialect author cannot introduce a rate-limit lockout.

```ts
export interface SqlDialect {
  name: string;
  tables: SqlTables;
  placeholder(i: number): string;            // "$1" (pg) | "?" (mysql/sqlite)
  supportsReturning: boolean;                // MySQL: FALSE — the engine then uses a locking txn
  forUpdate: string;                         // " FOR UPDATE"
  upsert(conflictCols, setClauses): string;  // ON CONFLICT … | ON DUPLICATE KEY UPDATE …
  deleteExpiredLimited(table, limit, i): string;
  ddl(): string;                             // the schema. The SDK emits it; the user never picks a type.
  preflight(driver): Promise<PreflightIssue[]>;
}
```

Copy `src/storage/sql/dialects/postgres.ts` and adjust. Then run the conformance suite against the
real engine (below) — that is the acceptance bar, and it is the *same* suite every other engine
passes.

**MySQL is the worked example of why this works.** It has the three worst SQL hazards, and all three
are absorbed by the dialect + generated DDL, never by the integrator:

| MySQL hazard | Where it is solved |
|---|---|
| **No `DELETE … RETURNING`** — atomic get-and-delete (the only defense against challenge REPLAY) can't be one statement | `supportsReturning: false`. The **engine** transparently switches to `SELECT … FOR UPDATE` + `DELETE` in a transaction. |
| **Case-INSENSITIVE default collation** — two distinct base58 keys, or `Acme`/`acme`, merge into one row | The DDL uses **`VARBINARY`**. (`utf8mb4_bin` is *not* enough — it is `PAD SPACE`, so `'k'` and `'k '` still collide.) |
| **Silent truncation** in non-strict mode — a clipped wallet blob is invalid JSON ⇒ the user loses every wallet | **`MEDIUMTEXT`**, plus **preflight refuses to boot** if strict mode is off. |

## 🐳 Testing against real engines — `npm run test:docker`

```bash
npm run test:docker    # spin up Postgres + MySQL + Redis, run the FULL suite, tear down
npm run docker:up      # leave them running while you iterate
npm run test:engines   # just the storage conformance suites
```

SQLite runs in-process on every `npm test` (no Docker) — it is a real SQL engine with real
transactions, so `SqlAuthStore` is exercised constantly. Postgres, MySQL, and Redis run in
`docker-compose.test.yml` and in CI.

> **🚨 Do not trust a mock, and do not trust one engine.** Both bugs that shipped in the first cut of
> the SQL engine were invisible to mocks, invisible on SQLite, invisible on Postgres, and only
> appeared when MySQL was run **for real**:
>
> 1. **A semicolon inside a DDL comment** (`-- epoch ms; filtered on every read`) shattered the
>    `CREATE TABLE` when the schema was split on `;`. Because the halves were `CREATE TABLE IF NOT
>    EXISTS`, the result was a **silently incomplete schema**, not a loud failure. (Fixed: use
>    `schemaStatementsFor()`, which strips comments before splitting.)
> 2. **`mysql2` returns `VARBINARY` columns as `Buffer`, not `string`.** Every key read back as
>    bytes, so every `===` was false — the email index never resolved and sessions never validated.
>    Silent, and only on MySQL. (Fixed in the driver: it decodes `Uint8Array` → UTF-8.)
>
> Atomicity, collation, expiry, and **wire format** are properties of the ENGINE. A mock only asserts
> that you mocked it the way you imagined — and the imagining was wrong both times.

## Writing a KV `StorageAdapter` — only for a real Redis-style store

1. **Mirror the existing shape.** `src/storage/redis.ts` and `kv.ts` are the pattern: a thin class
   over a structurally-typed `*Like` client interface, so the SDK never hard-depends on driver types.
   New drivers go in `peerDependencies` + `peerDependenciesMeta.optional: true` (as `ioredis` is
   today) and are loaded via lazy `import()`, so an unused driver is never bundled.
2. **Two keyspaces.** Strings, and the hash used by the email index.
3. **`del` removes the key from BOTH keyspaces** (real Redis `DEL` is type-agnostic).
4. The four expiry invariants are written into `src/storage/adapter.ts`'s doc comments — read them
   there, at the point of implementation.

## Verify it — the conformance suite IS the acceptance bar

```ts
import { authStoreConformanceCases } from "@tetrac/login-sdk/storage/conformance";

for (const c of authStoreConformanceCases(() => new MyStore(client), {
  // Supply only if your backend takes an injectable clock — it makes the expiry cases instant.
  // Omit against a real engine and the suite REALLY SLEEPS, which is what you want.
  advance: (ms) => { clock += ms; },
  supportsSweep: true,        // run the sweepExpired cases instead of silently skipping them
})) {
  it(c.name, () => c.run());  // framework-agnostic: Jest, Vitest, or node:test
}
```

Implementing the KV port instead? Wrap it and run the **same** suite — there is one bar:

```ts
authStoreConformanceCases(() => new KvAuthStore(new MyAdapter(client)));
```

Three things to hold yourself to:

- **Run it against a real engine in Docker, not a mock.** Atomicity, collation, and expiry are
  properties of the **engine**; a mock only asserts you mocked it the way you *imagined*. The SDK does
  this to itself: the suite runs against a live `redis:7-alpine` in CI, which is what makes
  `MemoryAdapter`'s "matches Redis" a **tested fact** rather than a code comment.
- **A suite that cannot fail is decoration.** The SDK keeps a *negative control* —
  `tests/storage-conformance-negative.test.ts` implements the store a competent engineer plausibly
  writes on the first try (counter with no window, get-then-delete challenge, expiry left to "the
  reaper", read-modify-write email index, case-folded keys) and asserts the suite **catches all
  seven** bugs. Do the same for your backend before you trust a green run.
- **Green ≠ safe.** The suite cannot test fail-closed (see above), and it cannot test your
  *deployment* — TLS, RLS, least privilege, query logs. Those are below.

## Reviewing a backend — the fast path

**Any backend** (a "no" is a blocker):

1. Does **every read** filter on expiry — `getSession`, `takeChallenge` — with **no reaper** required
   for correctness?
2. Is `takeChallenge` **atomic** (one statement, or an explicit transaction)?
3. Can two concurrent `putUser` calls for one email under different `appId`s **both** survive?
4. Is the email indexed and looked up via **`normalizeEmail()`**, not a case-insensitive collation?
5. Does `hitRateLimit` let a limited identifier through **after its window elapses**?
6. Are **all** values parameterized — and on Mongo, passed as scalar values, never as filter objects
   or update paths?
7. Do storage errors **propagate** rather than resolve to `{allowed: true}` / `null`?
8. Is `tokenHash` stored **as given** (already a digest) and `SessionValue` stored as typed fields?

**KV adapters, additionally:** does `incr` on an **expired** key return `1` and drop the stale TTL, in
one statement? Does `incr` on a **live** key leave its TTL alone? Does `del` clear both keyspaces?

**Then:** does the conformance suite pass **against a real engine**, and does the *deployment* clear
the hazards above (TLS `verify-full`, non-`public` schema on Supabase, DML-only role, no parameter
logging)?
