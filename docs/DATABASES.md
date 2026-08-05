# Choosing a database for `@tetrac/login-sdk`

**The short answer: PostgreSQL, unless you already run something else.** It is the best technical fit,
it covers the most deployment targets with one implementation (Supabase, Neon, RDS, Railway, Render,
Fly, CockroachDB — all the same wire protocol), and it is the most-used database among professional
developers. If you already run Redis, MySQL, or MongoDB, keep it — all three work.

This document is the honest comparison. It exists because "which database?" has a real answer, and
because a few popular choices **cannot** back this SDK at all — and you should find that out here, not
in production.

**Postgres, MySQL, and SQLite are shipped** — the setup is the same four steps for each, and you
write no queries, no schema, and no expiry logic:

```ts
import { createPostgresAuthStore, schemaFor } from "@tetrac/login-sdk/storage/sql";

// 1. npm i pg          (or mysql2 / better-sqlite3)
// 2. schemaFor("postgres") → run it against your DB. Don't hand-roll it; the types are load-bearing.
// 3. point the SDK at it — preflight runs here and REFUSES TO BOOT on the dangerous stuff:
const store = await createPostgresAuthStore({ client: pool });
export const { GET, POST } = createNextAuthRoutes({ store });
// 4. wire store.sweepExpired() to a cron (space + PII: rate-limit rows hold emails and IPs)
```

Redis/Upstash stay on `{ storage }`, unchanged.

> **Read this with [`ADR-002`](../PRD/ADR-002-uniform-backend-architecture.md).** Many of the "cons"
> below *used to* be your problem — a list of engine-specific traps you had to get right yourself.
> Under the uniform-backend architecture the SDK owns that logic, and your job shrinks to picking a
> driver. The cons that remain in this document are the **irreducible** ones: operational cost,
> latency, and deployment posture. Those no architecture can abstract away.

---

## 1. What the SDK actually needs (the capability gate)

An auth store is a small, boring workload — small values, point reads, no joins, no analytics. But it
needs four things, and **a store missing any one of them cannot back this SDK safely, no matter how
popular it is:**

| # | Capability | Used for | Why it's non-negotiable |
|---|---|---|---|
| 1 | **Atomic increment-and-decide** | rate limiting | A counter that can't count under contention is not a rate limiter. |
| 2 | **Atomic get-and-delete** (or a transaction) | single-use login challenges | This is the *only* thing preventing challenge **replay**. Two concurrent consumers must never both win. |
| 3 | **Expiry you can enforce on read** | sessions, challenges | See §2 — the trap. |
| 4 | **A write that can't lose a concurrent write** | the email→app index | Otherwise a registration silently vanishes. |

Everything else — SQL vs document, hosted vs self-run, serverless vs long-lived — is a preference.
These four are a gate.

## 2. 🚨 The trap that catches everyone: "native TTL"

Four of the databases below advertise a TTL feature. **In three of them it is not an expiry
mechanism — it is a garbage collector,** and treating it as expiry means **the SDK accepts expired
session tokens.**

| Database | What its "TTL" actually does |
|---|---|
| **Redis** | Exact. An expired key is gone, immediately, on every read path. ✅ |
| **MongoDB** | A background sweeper runs **~every 60 seconds**, best-effort under load. An expired session stays **readable and accepted** for up to a minute. |
| **DynamoDB** | Deletes **"within a few days"** of expiry. Days. |
| **Firestore** | ~24h — and Google's own docs state plainly that *expired documents continue to appear in queries*. |

**The rule, for every backend:** store an explicit `expires_at` and **filter on it in the read path**.
A TTL index, cron, or sweeper is **space reclamation only** — never the expiry authority.

This is why "does it have TTL?" is the wrong question, and why SQL databases having *no* TTL at all is
not a disadvantage: an honest absence is safer than a misleading feature.

---

## 3. The comparison

Capability columns are from each vendor's primary documentation. Adoption figures: Stack Overflow
Developer Survey 2025, and weekly npm downloads (registry API, pulled 2026-07-13).

| Database | Atomic incr | Real expiry | Atomic get+del | Adoption | Verdict |
|---|---|---|---|---|---|
| **PostgreSQL** | ✅ | ❌ none (honest) | ✅ `DELETE…RETURNING` | **55.6%** · `pg` 31.5M/wk | ⭐ **Best fit** |
| **Redis / Upstash** | ✅ native | ✅ **exact** | ✅ `GETDEL` | 28% · `ioredis` 19M/wk | ⭐ **Best fit** (already shipped) |
| **SQLite / libSQL** | ✅ | ❌ none | ✅ (≥3.35) | 37.5% | ✅ Great — dev & self-host |
| **MongoDB** | ✅ `$inc` | ⚠️ ~60s sweep | ✅ `findOneAndDelete` | 24% · 13.6M/wk | ✅ Works |
| **MySQL / MariaDB** | ✅ | ❌ none | ⚠️ **no `DELETE…RETURNING`** | 40.5% · 12.6M/wk | ✅ Works (hardest dialect) |
| **DynamoDB** | ✅ atomic counters | ⚠️ *"within a few days"* | ✅ `ReturnValues=ALL_OLD` | 9.8% | ✅ Works |
| **Cloudflare Durable Objects** | ✅ | ❌ (alarms) | ✅ transactional | — | ✅ Works — the *correct* Cloudflare answer |
| **Convex** | ⚠️ **sharded only** | ❌ none | ✅ serializable | — | ⚠️ Works, but it's a **component**, not a driver |
| **Firestore** | ✅ `increment()` | ⚠️ 24h, *still queryable* | ✅ transaction | 5.7% | ⚠️ Possible, weakest fit |
| **Cloudflare Workers KV** | ❌ **none** | ✅ | ❌ **none** | — | 🚫 **Cannot work** |
| **ClickHouse / BigQuery / Snowflake** | ❌ | — | ❌ | — | 🚫 **Wrong engine class** |

---

## 4. Per-database: the honest pros and cons

### ⭐ PostgreSQL — the default recommendation

**Covers in one implementation:** Supabase · Neon · AWS RDS/Aurora · Railway · Render · Fly ·
CockroachDB · self-hosted. They all speak the Postgres wire protocol.

| Pros | Cons |
|---|---|
| Cleanest capability fit of any engine — `DELETE…RETURNING` and `ON CONFLICT` give you atomic get-and-delete and atomic increment-and-decide in **single statements**, no transactions needed | **No native TTL.** You need a periodic sweep to reclaim space (the SDK ships one; you wire a cron) |
| Most-used database among professional developers (55.6%) — your team already knows it | Connection pooling is a real concern on serverless (§5) |
| You very likely **already run it**, so the SDK adds zero new infrastructure | **Supabase's default setup is dangerous** — see the warning below |
| Strong, boring, well-understood operational story | |

> 🚨 **Supabase users, read this.** Supabase auto-generates a **PostgREST API over every table in the
> `public` schema**, served to anyone holding the `anon` key — which is *shipped to browsers by
> design*. A table created the obvious way, with no RLS, is **world-readable**. It would contain your
> session records and every user's encrypted wallet blob. This is the single highest-severity
> misconfiguration available to you, it is reachable by following the **most natural** setup path, and
> it is **invisible from the app side** — everything appears to work perfectly.
>
> The SDK's generated schema puts the tables in a **dedicated non-`public` schema** and its startup
> preflight **refuses to boot** if it finds them in `public` on a `*.supabase.co` host. Use the
> generated schema; do not hand-roll it.

### ⭐ Redis / Upstash — already shipped, still excellent

| Pros | Cons |
|---|---|
| **Exact expiry.** The only engine here where TTL means what you think it means | **Another piece of infrastructure** to run, pay for, and monitor — if you don't already have one |
| Native `INCR` and `GETDEL` — the capability gate is met by primitives, not emulation | **Durability is a choice, not a default.** Redis is memory-first; a misconfigured instance can lose sessions and user records on restart |
| Sub-millisecond. The auth path never becomes your latency budget | Upstash is metered per-request; a busy auth path is a line item |
| Already supported (`RedisAdapter`, `UpstashAdapter`), zero migration | |

**Upstash vs. self-hosted:** Upstash for serverless/edge (HTTP-based, no connection pooling problem).
`ioredis` for a long-lived Node server or your own Redis.

> **Vercel KV is a sunset product.** Vercel deprecated it in Oct 2024 and now routes it to Upstash.
> `VercelKVAdapter` still works and is still supported — but point **new** deployments at Upstash.

### ✅ SQLite / libSQL (Turso) — dev and self-host

| Pros | Cons |
|---|---|
| **Zero infrastructure.** A file. Try the SDK with no database to provision | 🚫 **Cannot back a serverless deployment.** A local file cannot be shared across instances — each one gets its own private store, so sessions don't persist or replicate |
| Same SQL dialect family as Postgres — the capability fit is just as clean | `better-sqlite3` is **synchronous**: it blocks the event loop. Fine at self-host scale, not under load |
| Turso/libSQL makes it network-accessible if you outgrow the file | ⚠️ **The file is a credential store.** Mode `0600`, and **never** under a web-served directory — a `public/auth.db` is a one-request download of your entire auth store (and the `-wal`/`-shm` sidecars need the same treatment) |

**Use it for:** local development, single-VM self-hosting, demos, CI. **Not for:** Vercel, Lambda, or
anything horizontally scaled.

### ✅ MongoDB / Atlas

| Pros | Cons |
|---|---|
| The most-used document store in the JS ecosystem — likely already in your stack | ⚠️ **Its TTL index is a ~60s sweeper, not expiry** (§2). Get this wrong and you accept expired session tokens for a minute |
| `$inc` and `findOneAndDelete` meet the capability gate natively | No schema means no schema *enforcement* — the SDK's generated indexes are doing load-bearing work; don't skip them |
| Atlas is a genuinely good managed story | Slightly more per-operation latency than Postgres for this point-read workload |

### ✅ MySQL / MariaDB — works, but it's the hardest dialect

| Pros | Cons |
|---|---|
| #2 database overall (40.5%) — enormous installed base | ⚠️ **No `DELETE…RETURNING`.** Atomic get-and-delete needs an explicit transaction. Get this wrong and login challenges become **replayable** |
| Mature, well-understood ops | 🚨 **Its default collation is case-INSENSITIVE** (`utf8mb4_0900_ai_ci`). That would merge two distinct Solana addresses — and two distinct tenants — into one row |
| | 🚨 **Non-strict mode truncates silently** instead of erroring. A truncated wallet blob is invalid JSON, and the user is locked out of **every wallet in it**, with nothing pointing at the database |

> All three of these are handled by the SDK's generated schema and dialect (`VARBINARY` keys,
> `MEDIUMTEXT` values, strict mode asserted at startup, transactional get-and-delete). **This is
> exactly why you should not hand-write a MySQL backend.**

**Not PlanetScale.** It killed its free tier and its JS driver sits at ~191K weekly downloads — below
even the two *deprecated* Vercel packages. Target plain MySQL/MariaDB.

### ✅ DynamoDB — better than its reputation

| Pros | Cons |
|---|---|
| Genuinely clean capability fit — atomic counters, conditional writes, and `DeleteItem` with `ReturnValues=ALL_OLD` | ⚠️ **The worst TTL lag of any candidate**: deletion "within a few days." Read-path expiry filtering is not optional here, it is load-bearing |
| Serverless-native: no connection pooling problem at all | Single-table modelling is unusual if your team hasn't done it |
| Where AWS-native shops already live | Per-request pricing; vendor lock-in |

### ⚠️ Convex — works, but it is not a "database you point at"

Convex is an excellent engine (serializable transactions make atomic challenge-consume free, and its
writes can commit **transactionally with your app's own mutation** — stronger than anything Redis or
Postgres offers here). But it breaks the shape of every other option:

| Pros | Cons |
|---|---|
| Serializable transactions — the capability gate is met trivially | 🚫 **No external database access, ever.** All reads/writes must go through functions **deployed into your own `convex/` directory**. So this ships as a **Convex component** you install, not a driver you configure |
| Component writes commit atomically with your app's writes | ⚠️ **A hot counter is Convex's own documented anti-pattern** (OCC write conflicts — the mutation *throws* under exactly the burst traffic a rate limiter exists to survive). Rate-limit counters **must be sharded** |
| Auth-in-a-component is well-trodden (`@convex-dev/better-auth` et al.) | ❌ **No document TTL at all.** Expiry is entirely hand-rolled |
| | Metered per function call, and capped at 16 concurrent mutations on the free/starter tier |

**Verdict:** supported *as a component*, on demand — not as part of the standard driver lineup.

### ⚠️ Firestore — possible, but the weakest fit

Has atomic `increment()` and transactions, so it clears the gate. But its TTL is the most misleading
of the lot (**Google's docs say expired documents keep appearing in queries**), adoption among the
SDK's likely users is thin (5.7%), and it buys you nothing Postgres or Mongo don't. Only pick it if
you are already all-in on Firebase.

---

## 5. 🚫 What cannot work — and why you must not try

### Cloudflare Workers KV — **disqualified**

This is the one people reach for first, and it is the wrong choice in a way that fails *silently*:

- **No atomic increment.** Rate limiting would under-count — i.e. **not work** — and you would not
  notice.
- **No atomic get-and-delete.** Login challenges become **replayable**.
- **Eventually consistent**, with up to **60s** of global propagation, and a hard cap of **1
  write/sec/key**.

**If you're on Cloudflare, the answer is Durable Objects** — strongly consistent and transactional. Or
D1 (which is SQLite). Not Workers KV.

### ClickHouse / BigQuery / Snowflake / Databricks / TimescaleDB — **wrong engine class**

These dominate crypto engineering conversations because they're where **on-chain analytics** lives —
indexers, explorers, price history, chain forensics. They are OLAP: append-oriented, no atomic point
updates, no expiry semantics of this shape. An auth store is the exact opposite workload.

> This is worth stating plainly because the instinct is real: *"we're a crypto app, we use
> ClickHouse."* You do — for analytics. Your **auth tier** is a boring OLTP workload, and it should be
> boring. Coinbase's own engineering blog names *"MongoDB, Postgres, and Redis"*; Kraken advertises
> high-throughput PostgreSQL. Nobody authenticates users out of a columnar warehouse.

---

## 6. The two cons no architecture can remove

Everything above about dialects, collation, TTL semantics, and injection is **the SDK's problem, not
yours** (ADR-002). These two are genuinely yours:

**Connection pooling on serverless.** A `new Pool()` per request exhausts your database's connection
limit under concurrency, and the failure mode is a hard outage, not gradual degradation. Use a
**module-level singleton**, or a serverless-native driver (`@neondatabase/serverless`,
`@vercel/postgres`, Upstash's HTTP client). Redis/Upstash/DynamoDB sidestep this entirely.

**Deployment posture.** TLS that actually *verifies* the server (`sslmode=verify-full` — plain
`require` encrypts but accepts **any** certificate, so it does nothing against an active MITM), a
least-privilege database role, and query logs that don't capture parameters. The SDK's **preflight
check** enforces what it can at startup and refuses to boot on the dangerous ones — but it cannot
audit your VPC.

---

## 7. Decision guide

```
Already running Redis?            → keep it. Nothing to do.
Already running Postgres/Supabase → use it. Best fit anyway.
Already running MySQL or Mongo?   → use it. Both fully supported.
On AWS, serverless-native?        → DynamoDB.
On Cloudflare?                    → Durable Objects.  (NOT Workers KV.)
Local dev / single-VM self-host?  → SQLite.
Starting fresh, no constraints?   → PostgreSQL (via Supabase or Neon).
```

**The point of the architecture is that this choice is cheap and reversible.** Switching backends is a
one-line change at the route — the SDK's behavior, security properties, and conformance guarantees are
identical across every option in the ✅/⭐ rows. Pick the one you already operate.
