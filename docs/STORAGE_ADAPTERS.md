# Storage backends — the contract

`@tetrac/login-sdk` never imports a database client. The server layer depends on an interface, and
`createNextAuthRoutes({ store })` accepts **any** implementation. So backing the SDK with your own
database is supported, and always was.

**The hard part was never the code.** It is that a reasonable, working-looking backend can be
*catastrophically* wrong — passing every smoke test, then days later permanently locking users out,
accepting expired sessions, replaying a login challenge, or silently merging two accounts. This
document is the contract that prevents that, and `@tetrac/login-sdk/storage/conformance` is the
executable version of it.

---

## 1. Which interface do I implement?

There are two. Picking the wrong one is the most expensive mistake available here.

| Port | What it is | Implement it when |
|---|---|---|
| **`AuthStore`** ← **the extension point** | The **domain** port: users, sessions, challenges, and a single atomic rate-limit *decision*. | **Almost always.** Any real database: Postgres/Supabase, MySQL, SQLite, MongoDB, DynamoDB, Convex, Durable Objects. |
| `StorageAdapter` | The **KV** port: 10 Redis-shaped primitives (`get`/`set`/`del`/`incr`/`expire`/`getdel`/`hget`/`hset`/`hdel`/`hgetall`). | Only when your backend genuinely **is** a Redis-style KV store — i.e. it has native atomic `INCR`, native TTL, and atomic `GETDEL`. |

`KvAuthStore` adapts any `StorageAdapter` into an `AuthStore`, which is how the built-in Redis,
Upstash, Vercel KV, and Memory backends work. **You almost certainly want `AuthStore`.**

### Why the split exists

`StorageAdapter` is named for what it *is* (a key-value store) rather than for what it is *for*
(authentication state). That inverts the dependency: every backend has to **emulate Redis** instead
of doing what it is actually good at.

The clearest case is rate limiting. `incr(key)` is a **primitive**, not a **decision** — it hands
your backend a mechanism and denies it the intent. A rate-limit counter is "many writes to one row",
which on an OCC engine (Convex, and any optimistic-concurrency store) is the *documented
anti-pattern*: writes conflict, retry, and eventually **throw** — under exactly the burst traffic a
rate limiter exists to survive. The correct fix there is a **sharded** counter, which is trivial for
a backend asked `hitRateLimit(...)` and **impossible** for one asked `INCR`.

Design rationale in full: [`PRD/ADR-001-storage-seam.md`](../PRD/ADR-001-storage-seam.md).

---

## 2. The `AuthStore` interface

```ts
import type { AuthStore } from "@tetrac/login-sdk/storage";

interface AuthStore {
  // users
  getUser(appId: string, publicKey: string): Promise<UserData | null>;
  putUser(user: UserData): Promise<void>;            // upsert + maintain the email index
  getPublicKeyByEmail(appId: string, email: string): Promise<string | null>;

  // challenges — single-use, TTL-bound
  putChallenge(appId, publicKey, challenge: string, ttlSeconds: number): Promise<void>;
  takeChallenge(appId, publicKey): Promise<string | null>;   // ATOMIC get-and-delete

  // sessions — keyed by the token's SHA-256 digest, never the token itself
  putSession(appId, tokenHash, value: SessionValue, ttlSeconds): Promise<void>;
  getSession(appId, tokenHash): Promise<SessionValue | null>;
  deleteSession(appId, tokenHash): Promise<void>;

  // rate limiting — ONE atomic call returning a DECISION
  hitRateLimit(bucket: RateLimitBucket, windowSeconds, maxAttempts): Promise<RateLimitResult>;

  // OPTIONAL — callers feature-detect
  sweepExpired?(limit?: number): Promise<number>;
  close?(): Promise<void>;
}
```

Wire it up:

```ts
import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
export const { POST, GET } = createNextAuthRoutes({ store: new MyStore(client) });
```

---

## 3. The four invariants

Get these wrong and the SDK is insecure, not merely slow. Each is a conformance case.

### 3.1 🚨 Expiry is enforced **on read**

`getSession` and `takeChallenge` MUST return `null` for an expired value **even if no sweeper has
ever run.**

The SDK's `verifySession` accepts any non-null value `getSession` returns — it performs no
independent expiry check. So a backend that leaves expired sessions readable **silently extends the
life of every leaked bearer token.**

This is not hypothetical, and "native TTL" is a trap:

| Backend | TTL reality |
|---|---|
| MongoDB | TTL index is swept **~every 60s**, best-effort under load |
| DynamoDB | TTL deletion is **"within a few days"** |
| Firestore | 24h — and Google's docs state plainly that *expired documents continue to appear in queries* |
| Convex | **No document TTL at all** |

> A TTL index, cron, or `sweepExpired` is **space reclamation only**. It is never the expiry
> authority. Store an explicit `expiresAt` and filter on it in the read path — *in addition to* any
> native TTL.

### 3.2 🚨 `takeChallenge` is atomic

It is the sole mechanism closing the challenge-replay race. N concurrent callers, **at most one**
observes the value.

- Postgres / SQLite ≥3.35: `DELETE … RETURNING value` — one statement.
- MySQL has **no** `DELETE … RETURNING`: use an explicit transaction (`SELECT … FOR UPDATE`, then
  `DELETE`). Getting this wrong turns a single-use challenge into a replayable one.
- Compare the value **in the SDK**, not in your backend — `consumeChallenge` does a constant-time
  compare on the returned string.

### 3.3 🚨 `putUser` must not lose a concurrent write

The email index maps `email → {appId: publicKey}`. Two concurrent registrations of the **same email
under different `appId`s** must both survive.

A backend that reads the whole index, merges in JS, and writes it back **reintroduces exactly the
race this design eliminates** — and a registration silently vanishes. Use a row/document per
`(email, appId)` with a unique index, and upsert.

> **MongoDB trap:** do **not** model the index as `$set: {["fields." + appId]: pk}`. The `appId`
> regex permits `.`, and the SDK's own *recommended* format is a domain (`"myapp.example"`) — Mongo
> reads the dot as **nesting**, so tenants `myapp` and `myapp.example` collide and one destroys the
> other. Give the index its own collection keyed `{key, field}`, passing both as **scalar values**.

### 3.4 🚨 Errors fail **closed**

Propagate them. `null` means *"the backend answered, and it is absent"* — **never** *"the backend
did not answer."*

Pooled SQL clients fail in ways an in-process Redis client mostly doesn't (pool exhaustion,
connection reset, failover), so the reflex is a `catch` that returns a benign default. Every one of
those silently switches off a security control:

| Swallowed error | What actually happens |
|---|---|
| `hitRateLimit` returns `{allowed: true}` | **rate limiting is disabled** — under exactly the load that broke it |
| `putSession` swallows a write failure | a token is issued that was never stored ⇒ every later request 401s |
| `getUser` returns `null` on failure | "backend is down" becomes indistinguishable from "no such user" |

Bounded retries for transient connection errors are fine. Converting an error into a value is not.

---

## 4. Things that will bite you

- **Keys are case-sensitive.** `appId` and base58 public keys are compared byte-exactly. MySQL's
  default collation (`utf8mb4_0900_ai_ci`) is case-**insensitive**, so tenants `Acme`/`acme` become
  one namespace and two distinct Solana addresses become one row. Use a **binary, non-padding**
  collation: `VARBINARY`, or `utf8mb4_0900_bin`. **Never `utf8mb4_bin`** — it is `PAD SPACE`, so
  `'k'` and `'k '` compare equal.
- **Emails are matched via the exported `normalizeEmail()`** (lowercase + trim). Route both the write
  and the read through it. Do **not** delegate case-insensitivity to a column collation — that would
  also case-fold the `appId` and the public key.
- **Size the value column for ~15 KB.** A `UserData` blob holds up to 64 encrypted wallets. MySQL
  `TEXT` in non-strict mode **truncates silently**, producing invalid JSON — the record then reads
  back as `null` and the user is **permanently locked out of every wallet in it**, with nothing
  pointing at the database. Use `MEDIUMTEXT` and `STRICT_ALL_TABLES`.
- **Parameterize everything.** Values carry attacker-influenced substrings (emails, public keys, a
  request-supplied `appId`). On MongoDB the injection surface is *structural*, not lexical: pass
  `key`/`field` only as **scalar string values** in a filter — never as a filter object (an
  attacker's `{"$gt": ""}` becomes an **operator** and matches every row), never as an update-document
  key, never near `$where`.
- **Sweep for space — and for privacy.** Rate-limit buckets embed **emails and IPs**. Redis evicts
  them in 60s; a durable backend keeps them, and in every backup, until something deletes them. That
  is a data-retention obligation, not a housekeeping backlog item. Implement `sweepExpired`.

---

## 5. Verify it — the conformance suite

This is the acceptance bar. It is framework-agnostic (it returns cases rather than calling
`describe`/`it`), so run it under Jest, Vitest, or `node:test`:

```ts
import { authStoreConformanceCases } from "@tetrac/login-sdk/storage/conformance";

for (const c of authStoreConformanceCases(() => new MyStore(client))) {
  it(c.name, () => c.run());
}
```

Implementing the KV port instead? Wrap it and run the **same** suite — there is one bar:

```ts
authStoreConformanceCases(() => new KvAuthStore(new MyAdapter(client)));
```

Options:

```ts
authStoreConformanceCases(makeStore, {
  advance: (ms) => { clock += ms; },  // if your backend takes an injectable clock; otherwise it really sleeps
  supportsSweep: true,                // run the sweepExpired cases instead of skipping them
});
```

> **Run it against a real engine in Docker, not a mock.** Atomicity, collation, and expiry are
> properties of the **engine** — a mock only asserts that you mocked it the way you imagined. This is
> not pedantry: every invariant in §3 is one that a mock will happily let you get wrong.

---

## 6. Backend selection

The gate is capability, not popularity: the SDK needs **atomic increment**, **expiry**, **atomic
get-and-delete**, and **per-row atomic index writes**.

| Backend | Verdict |
|---|---|
| **PostgreSQL** (→ Supabase, Neon, RDS, Railway, Render, Fly, CockroachDB) | **Best fit.** One implementation covers all of these — they share the Postgres wire protocol. No native TTL, so expiry-on-read + a sweeper are yours to build. |
| **MongoDB / Atlas** | Good — with the read-path expiry filter and a separate index collection (§3.3). |
| **SQLite / libSQL (Turso)** | Good. Dev / self-host / single-instance only; the file is a credential store (mode `0600`, never under a web-served directory). |
| **DynamoDB** | Good — cleaner than its reputation. TTL lag is the worst of any candidate; read-path filtering is non-negotiable. |
| **MySQL / MariaDB** | Workable, hardest. No `DELETE … RETURNING`, collation traps, silent truncation. |
| **Convex, Durable Objects** | `AuthStore` only. Convex ships as a **Convex component** (all DB access must go through functions deployed in the customer's own `convex/` directory), and its rate-limit counter **must be sharded**. |
| 🚫 **Cloudflare Workers KV** | **Cannot back this SDK.** No atomic increment, no atomic get-and-delete, up to 60s propagation, 1 write/sec/key. Rate limiting would silently not work and challenges would be **replayable**. Use **Durable Objects**. |
| 🚫 **ClickHouse / BigQuery / Snowflake** | Wrong engine class (OLAP). No atomic point updates. |

> **Deployment note — Supabase 🚨** Supabase auto-generates a PostgREST API over every table in the
> `public` schema, served to anyone holding the browser-shipped `anon` key. A table created the
> obvious way, with no RLS, is **world-readable** — and it holds session records and encrypted wallet
> blobs. Create the tables in a **dedicated, non-`public` schema**, `REVOKE` from
> `anon`/`authenticated`, and enable RLS with an explicit policy for a dedicated DML-only role. Do
> not connect as `service_role`: it is a global admin bypass over the entire database.
