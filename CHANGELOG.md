# Changelog

All notable changes to `@tetrac/login-sdk`.

---

## `0.6.0`

### 🐘 PostgreSQL, MySQL, and SQLite are now first-class — and the setup is identical for each

New subpath: **`@tetrac/login-sdk/storage/sql`**.

```ts
import { createPostgresAuthStore, schemaFor } from "@tetrac/login-sdk/storage/sql";
const store = await createPostgresAuthStore({ client: pool });   // preflight runs here
export const { GET, POST } = createNextAuthRoutes({ store });
```

One function covers **Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly, and CockroachDB** —
they all speak the Postgres wire protocol. `createMysqlAuthStore` and `createSqliteAuthStore` are the
same shape.

**You write no queries, no schema, and no expiry logic.** That is the point
([ADR-002](PRD/ADR-002-uniform-backend-architecture.md)): the SDK now *owns* the correctness rules
instead of exporting them. Previously, backing the SDK with Postgres meant implementing nine methods
and independently getting right expiry-on-read, atomic challenge consume, rate-limit window
semantics, no-lost-write on the email index, email normalization, binary collation, column sizing,
and injection safety — **eight rules, per database**. That is a security exam, not an extension
point, and it is why every new engine turned into a fresh security review.

Now there is **one engine** (`SqlAuthStore`) plus a ~30-line **dialect** per database. Adding an
engine can no longer introduce a rate-limit lockout, because a dialect author never writes a rate
limiter.

- **The SDK emits the schema** (`schemaFor("postgres" | "mysql" | "sqlite")`). Don't hand-roll it —
  the column types and keys are load-bearing. The email index is keyed `(email, app_id)`, so a lost
  write is *structurally impossible* rather than merely avoided.
- **MySQL's three notorious hazards are handled in the dialect**, not by you: no `DELETE…RETURNING`
  (the engine switches to a `SELECT … FOR UPDATE` transaction, so challenges still can't be
  replayed), a case-insensitive default collation (the DDL uses `VARBINARY` — note `utf8mb4_bin` is
  *not* enough, it's `PAD SPACE`), and silent truncation in non-strict mode (`MEDIUMTEXT`, plus
  preflight refuses to boot).

### 🛡️ Preflight — misconfigurations now fail the deploy, not the users

Checks run at construction and **refuse to boot** rather than living in a paragraph someone skimmed:

- 🚨 **Supabase's `public` schema.** Supabase serves a PostgREST API over every `public` table to
  anyone holding the browser-shipped `anon` key. These tables hold session records and every user's
  encrypted wallet blob — that is **world-readable**, reachable by the most natural setup path, and
  **invisible from the app side**. The SDK defaults to a dedicated `tetrac` schema and refuses
  `public` outright.
- 🚨 **MySQL not in strict mode** (silent truncation ⇒ a user locked out of every wallet they own).
- 🚨 **A SQLite file under `public/`** — a one-request download of your entire auth store.
- ⚠️ Warns on a nondeterministic Postgres collation, and on a world-readable SQLite file.

### 📚 New: [`docs/DATABASES.md`](docs/DATABASES.md) — which database, and why

Honest pros/cons per engine. Two things worth knowing before you choose:

- **Cloudflare Workers KV cannot back this SDK.** No atomic increment, no atomic get-and-delete.
  Rate limiting would silently not work and login challenges would be **replayable**. Use Durable
  Objects.
- **"Native TTL" is a trap in three of four engines.** Mongo sweeps ~60s late, DynamoDB *"within a
  few days"*, and Firestore's own docs say expired documents keep appearing in queries. Treating any
  of them as expiry means **accepting expired session tokens**. (The SDK always filters expiry on the
  read path, so this is handled — but it's why you shouldn't hand-roll a backend.)

### ✅ Tested against real engines, not mocks

The full 24-case conformance suite runs against **real SQLite** on every `npm test` (in-process, no
Docker) and against **real Postgres** in CI. Same engine code, different dialect — which is the
claim of ADR-002, tested. Plus dialect-level invariants asserted for all three engines: placeholder/
parameter parity, and that **no value is ever interpolated into SQL** (an injection test at the
engine, for every dialect at once).

### 📝 Notes

- `pg`, `mysql2`, and `better-sqlite3` are **optional peer dependencies**, loaded structurally — the
  SDK never imports them, and nothing is bundled into `dist`. A consumer who doesn't use them pays
  nothing.
- Redis/Upstash (`{ storage }`) is unchanged and fully supported.

---

## `0.5.1`

### 🐛 Fixed — a Web3 login no longer mints a second Solana wallet

**Who is affected:** any account created by logging in with a connected Solana wallet
(Phantom / Solflare / Backpack / Ledger) on `0.5.0` or earlier.

`connectWallet()` and `registerWithWallet()` were generating an **embedded Solana `funds` wallet**
even though the wallet the user just connected *is* their Solana funds wallet (it becomes
`UserData.publicKey`). That produced a wallet the user never asked for, whose private key the SDK
held and the export UI would happily reveal.

**The more serious half:** `useActiveWallet()` resolved the Solana wallet from the
`externalSolanaAddress` prop, which an app pipes in from `@solana/wallet-adapter`. That prop is
`null` whenever the adapter isn't connected in the current browser session — but the SDK session
persists in `localStorage` and outlives it. So a returning Web3 user, before re-approving their
wallet, would get the **stray embedded wallet's address** back. An app rendering that as a deposit
address would send the user's funds to a wallet they don't know they own.

- `connectWallet` / `registerWithWallet` no longer generate a Solana `funds` wallet. Solana
  `signing` and the EVM wallets still generate — those are genuinely additional keys a connected
  Solana wallet cannot provide.
- `useActiveWallet()` / `useWallets()` now resolve a Web3 account's Solana wallet from the **record**
  (`authMethod === "wallet"` → `user.publicKey`), never from the adapter prop.
- **New:** `WalletEntry.isIdentity` — use this, not `role === "funds"`, to answer *"which wallet is
  the user?"*. `role === "funds"` is ambiguous on Web3 accounts and is what caused this bug.

**Existing accounts.** The stray wallet is **not** deleted or hidden. It is a real key that may hold
a real balance — precisely because the UI was presenting it as the funds wallet — so hiding it would
have stranded those funds. It still appears in `useWallets()` with `isIdentity: false`, so you can
surface it and let the user sweep it.

---

## `0.5.0`

> ### ⚠️ Upgrading logs every user out, once.
>
> Session tokens are now stored as **SHA-256 digests**, so the session keys written by `0.4.x` no
> longer resolve. Every live session is dead on deploy and users must sign in again.
>
> It is self-healing (the session TTL is 4h; each login already revoked the prior token) and there is
> **no data migration, no backfill, and no dual-read window** — a dual-read fallback would keep raw
> tokens readable and accepted for the length of that window, which is the exact thing this release
> exists to stop. **Nothing else about upgrading is breaking:** the public API, the client bundle, and
> `createNextAuthRoutes({ storage })` are all unchanged.

### 🔒 Security — the store no longer holds replayable credentials

The SDK was storing the **raw session bearer token** at rest, in **two** places: as the session key,
*and* inside the `UserData` blob (`user.authToken`). Anyone who could read the store — a backup, a
read replica, an analytics sync, a query log, another service sharing the DSN — could replay those
tokens directly. No cracking step, no escalation.

That was defensible when the store was a private, ephemeral Redis. It is not the posture of a
database that gets backed up, replicated, and dumped to staging.

Both locations now store `SHA-256(token)`. The token is 256 bits of CSPRNG output, so a bare hash is
preimage-secure with no KDF — the construction used for API keys. A read of the store now yields
**digests, not credentials**: the attacker learns *that* a session exists and who owns it, and cannot
become that user.

> Hashing only the *key* — the obvious fix — would have been a **false fix**: the raw token would
> still have been readable in every `UserData` blob.

**Not addressed by this** (and stated plainly in the threat model): the store still holds every
user's encrypted wallet blob. That is ciphertext behind PBKDF2, but it is an offline-cracking corpus.
Your `securityLevel` is what decides how long it holds.

### 🏗️ New — the `AuthStore` port: back the SDK with any database

`StorageAdapter` was named for what it *is* (a key-value store) rather than what it is *for* (auth
state), which forced every backend to **emulate Redis** instead of doing what it is good at. The
clearest symptom: `incr(key)` is a *primitive*, not a *decision*, so a backend that needs to shard a
contended rate-limit counter (any optimistic-concurrency engine) **cannot** — the port forbids the
only correct implementation.

- **New `AuthStore`** (`@tetrac/login-sdk/storage`) — the domain port: users, sessions, challenges,
  and one atomic rate-limit *decision* (`hitRateLimit`). Implement this to back the SDK with
  Postgres/Supabase, MySQL, SQLite, MongoDB, DynamoDB, Convex, or Durable Objects.
- **`createNextAuthRoutes({ store })`** accepts it. **`{ storage }` still works, unchanged** — a
  `StorageAdapter` is auto-wrapped in the new `KvAuthStore`. No existing app changes a line, and all
  four built-in adapters are untouched.
- **New conformance suite** (`@tetrac/login-sdk/storage/conformance`) — the acceptance bar for a
  custom backend. Framework-agnostic (Jest, Vitest, or `node:test`). It exists because a
  plausible-looking backend can be catastrophically wrong: permanently locking users out, accepting
  expired sessions, or replaying login challenges, all while passing a smoke test.
- Read [`docs/STORAGE_ADAPTERS.md`](docs/STORAGE_ADAPTERS.md) before writing one.

No first-party SQL backend ships in `0.5.0` — Postgres/Supabase is `0.6.0`. This release is the seam
they plug into.

### ✨ Added

- **`sweepExpired?()`** — reclaim expired entries. Implemented on `MemoryAdapter`, which expires
  *lazily* and therefore genuinely leaked in a long-running process (rate-limit counters and expired
  sessions are typically never read again, so nothing ever triggered their removal). Space only —
  never the expiry authority.
- **`close?()`** — release pooled connections. `RedisAdapter` holds a live ioredis socket and until
  now there was **no way to release it**: Jest hung on the open handle and long-lived servers leaked
  a connection per reload.
- Both are **optional** and feature-detected, so every existing adapter stays valid.

### 🐛 Fixed

- `MemoryAdapter.del` now clears the hash keyspace too, matching real Redis `DEL` (it previously
  cleared only the string map — silently diverging from `RedisAdapter`, which made the "normative
  reference implementation" not actually normative).
- `/login` now validates `body.email` before it reaches a storage key, matching `/register`. Inert on
  Redis; on a SQL backend an unvalidated 1 MB email is an unauthenticated 500 or a silent key
  truncation.

### 📝 Notes

- **Vercel KV is now documented as legacy.** Vercel sunset it in Oct 2024 and routes it to Upstash.
  `VercelKVAdapter` still works and is still supported — but new deployments should use **Upstash**,
  and `resolveStorageAdapter()` deliberately prefers Upstash when both are configured.
- The conformance suite runs against a **real Redis** in CI, not a mock. Atomicity and expiry are
  properties of the engine; a mock only asserts you mocked it the way you imagined.
