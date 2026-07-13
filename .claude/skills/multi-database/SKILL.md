---
name: multi-database
description: Implement, review, or debug a storage backend for `@tetrac/login-sdk` — either an `AuthStore` (the domain port, v0.5.0+; the right choice for Postgres/Supabase, MongoDB, DynamoDB, Convex, Durable Objects) or a `StorageAdapter` (the legacy KV port behind Redis/Upstash/Vercel KV). Encodes the non-obvious correctness contract a backend MUST honor: expiry-on-read, the permanent-rate-limit-lockout bug, atomic get-and-delete, per-field hash atomicity, binary/non-padding collation, key sizing, injection safety, and fail-closed error handling. Use when — writing or reviewing a storage backend; picking a database for the SDK; wiring Postgres/Supabase/SQLite/Mongo/MySQL/DynamoDB/Convex behind the SDK; running the conformance suite; or debugging symptoms like "user permanently rate-limited", "session accepted after it expired", "challenge replayed", "email index lost a write", "two accounts collided", "wallets disappeared / user locked out of their wallets", "Supabase table is world-readable", "Convex write conflict / OCC". Triggers — "add a database", "Postgres adapter", "Supabase auth store", "Convex backend", "custom StorageAdapter", "AuthStore", "bring my own database", "multi-db", "storage conformance".
---

# Backing `@tetrac/login-sdk` with a database

The server layer never imports a database client — it depends on an interface, and
`createNextAuthRoutes()` accepts any implementation. So backing the SDK with a new database is
*already* possible. The hard part was never the code.

**The hard part is that a reasonable, working-looking backend can be catastrophically wrong.** Every
hazard below produces a backend that passes a smoke test and then, days later, permanently locks
users out, accepts expired sessions, or silently corrupts one account into another. Each is a
required conformance case.

## Which port do I implement? — read this first

There are **two**, and picking the wrong one is the most expensive mistake available.

| Port | What it is | Implement it when |
|---|---|---|
| **`AuthStore`** (`src/storage/store.ts`) — **the real extension point** | The **domain** port: `getUser`, `putUser`, `getPublicKeyByEmail`, `putChallenge`, `takeChallenge`, `putSession`, `getSession`, `deleteSession`, **`hitRateLimit`**, + optional `sweepExpired`/`close`. | **Almost always.** Any real database: Postgres/Supabase, MongoDB, DynamoDB, SQLite, MySQL, Convex, Durable Objects. |
| **`StorageAdapter`** (`src/storage/adapter.ts`) | The **KV** port: 10 Redis-shaped primitives (`get`/`set`/`del`/`incr`/`expire`/`getdel`/`hget`/`hset`/`hdel`/`hgetall`). `KvAuthStore` wraps any of these into an `AuthStore`. | Only when the backend genuinely **is** a Redis-style KV store with native atomic `INCR`, TTL, and `GETDEL`. |

**Why this split exists (v0.5.0 / `PRD/ADR-001-storage-seam.md`):** `StorageAdapter` is named for
what it *is* (a key-value store), not what it is *for* (auth state). That forces every backend to
**emulate Redis** rather than do what it's good at. The clearest proof is `incr`:

> A rate-limit counter is *many writes to one row*. On **Convex**, that is the *documented
> anti-pattern* — OCC write conflicts, and the mutation eventually **throws** under exactly the burst
> traffic a rate limiter exists to survive. The correct fix is a **sharded** counter. But
> `incr(key)` is a *primitive*, not a *decision* — so the KV port **forbids the only correct
> implementation.** `hitRateLimit(bucket, window, max)` allows it, invisibly.

**Consequence: six of the seven hazards below are artifacts of the KV port.** They are listed
because Redis-family adapters and `KvAuthStore` still live in that world — but if you are
implementing `AuthStore` against a real database, most of them **cannot occur**, because you are
storing typed fields instead of emulating Redis on opaque strings. Each hazard is tagged.

## The one rule for the KV port

> **A key is an opaque, attacker-influenced byte string. Store it; never parse, split, interpret,
> truncate, case-fold, or path-split it.**

Keys are assembled by `appScoped()` (`src/server/keys.ts`) and embed base58 public keys, hex tokens,
email addresses, and a tenant `appId` that may come straight off the request. The `appId` is
validated upstream to exclude `':'`, so namespace escape is already handled — **an adapter must not
add validation, and must not add interpretation.** (Under `AuthStore` this rule mostly evaporates:
`appId` and `publicKey` are *typed arguments*, not substrings of a synthetic key.)

---

## The seven ways a backend goes wrong

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
disagree, `MemoryAdapter` (which matches real Redis) is right.

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

---

## Errors must fail **closed**

`checkRateLimit` has no `try`/`catch`: if `incr` throws, the request 500s. That is **correct** — a
rate limiter that cannot count must not grant permission.

Pooled SQL clients fail in ways an in-process Redis client mostly doesn't (pool exhaustion,
connection reset, failover), so the reflex is a `catch` returning a benign default. **Every one of
those is a security control silently switching off:**

| Swallowed error | What actually happens |
|---|---|
| `incr` returns `0`/`1` on failure | `count <= maxAttempts` ⇒ **rate limiting is disabled**, under exactly the load that broke it |
| `set` swallows a write failure | `issueSession` returns a token that was never stored ⇒ every later request 401s |
| `get`/`hget` return `null` on failure | "backend is down" is indistinguishable from "key is absent" |

> **Adapters propagate storage errors.** `null` means *"the backend answered, and the key is
> absent"* — **never** *"the backend did not answer."* Bounded retries for transient connection
> errors are fine; converting an error into a value is not.

---

## Deployment hazards that are not in the code

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

## Writing the adapter

1. **Mirror the existing shape.** `src/storage/redis.ts` and `kv.ts` are the pattern: a thin class
   over a structurally-typed `*Like` client interface, so the SDK never hard-depends on driver types.
   New drivers go in `peerDependencies` + `peerDependenciesMeta.optional: true` (as `ioredis` is
   today) and are loaded via lazy `import()`, so an unused driver is never bundled.
2. **Two keyspaces, two tables.** `ttc_kv (key PK, value, expires_at)` and
   `ttc_kv_hash (key, field, value, PRIMARY KEY (key, field))`.
3. **`del` removes the key from BOTH keyspaces** (real Redis `DEL` is type-agnostic).
4. **Optional methods:** `close?()` (release pooled connections; omit for REST clients) and
   `sweepExpired?(limit?)` (space only — never the expiry authority). Callers feature-detect, so
   omitting them is valid.
5. **Run the conformance suite.** It is exported for exactly this purpose and is the acceptance bar:

```ts
import { authStoreConformanceCases } from "@tetrac/login-sdk/storage/conformance";

// Implementing AuthStore (the normal case) — test it directly:
for (const c of authStoreConformanceCases(() => new MyStore(client))) {
  it(c.name, () => c.run());   // framework-agnostic: Jest, Vitest, or node:test
}

// Implementing the KV StorageAdapter instead? Wrap it and run the SAME suite —
// there is only one acceptance bar:
for (const c of authStoreConformanceCases(() => new KvAuthStore(new MyAdapter(client)))) {
  it(c.name, () => c.run());
}
```

Test against a **real engine in Docker**, not a mock. Atomicity, collation, and expiry are
properties of the **engine** — a mock only asserts that you mocked it the way you imagined.

## Reviewing an adapter — the fast path

Ask these seven questions in order. Each maps to a hazard above, and a "no" is a blocker:

1. Does `incr` on an **expired** key return `1` and drop the stale TTL — **in one statement**?
2. Does **every read** filter on expiry, with no reaper required for correctness?
3. Is `getdel` **atomic** (one statement, or an explicit transaction)?
4. Is `hset` a **per-field** upsert — not read-modify-write, and not a dotted Mongo path?
5. Are the key/field columns **binary and non-padding**, and ≥512 bytes?
6. Are **all** values parameterized, with nothing interpolated into a query or a Mongo path?
7. Do storage errors **propagate** rather than resolve to a benign default?

Then: does `del` clear both keyspaces, and does the conformance suite pass **against a real engine**?
