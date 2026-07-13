# Feature PRD — Pluggable database providers / Bring-Your-Own-Database (`0.6.0`)

> **Retargeted to `0.6.0`.** The backend-agnostic groundwork this document depends on — the session-
> token hashing (§4.6), the optional `close?()` / `sweepExpired?()` methods (§3.3), the conformance
> suite (§7), the `MemoryAdapter.del` fix (§3.8), and the `/login` key-validation prerequisite
> (§3.9) — ships first, **Redis-only**, in **[`PRD/v0.5.0-PRD.md`](../PRD/v0.5.0-PRD.md)**. No new
> database provider ships in `0.5.0`. This document remains the design for the adapters themselves.

Let a developer back `@tetrac/login-sdk` with **whatever database they already run** —
PostgreSQL (incl. Supabase), MySQL, SQLite, MongoDB, Couchbase, or a fully custom store —
instead of provisioning Redis/Upstash/Vercel KV solely for this SDK. Today that is
*technically* possible (the server layer depends on an interface, not a Redis client) but it
is undocumented, unverified, and has no first-party adapter outside the Redis family. This
PRD formalizes the existing extension point, spells out the **non-obvious correctness
contract** a new backend must honor, and ships batteries-included adapters for it.

- **Status:** 📝 Proposed. Not yet implemented.
- **Shape:** **Additive.** No change to `StorageAdapter`'s 10 required method signatures; no
  behavior change for any currently-configured deployment; no new runtime `dependencies`.
  Any app on `0.4.x` upgrades with zero code changes. Three existing files need a source edit,
  all of them small and none of them behavior-changing for a current deployment:
  1. `src/storage/resolve.ts` — the production guard is *widened* to recognize the new
     backends (§6). "Widened" is the operative word: no env-var combination that resolves
     successfully today resolves differently (or fails) afterward.
  2. `src/storage/memory.ts` — `del` must also clear the hash keyspace, to match Redis (§3.8).
  3. `src/server/routes.ts` — the email-login path builds storage keys from an **unvalidated,
     unbounded** `body.email` (§3.9). Harmless against Redis; against a `VARCHAR(512)` column it
     is an unauthenticated 500 (Postgres) or a silent key truncation (MySQL). This is a
     **prerequisite**, not a nice-to-have: §3.6's column sizing is only sound once it holds.
- **One recommended change beyond the adapter layer (§4.6):** store `SHA-256(token)` in the
  session key instead of the token itself. It is the single highest-leverage security change in
  this document — it is what turns §4.1 (a world-readable Supabase table) from *instant account
  takeover for every user* into *a table of useless digests*. It is scoped separately because it
  touches `src/server/session.ts` and logs every user out once on upgrade.
- **Driver:** Product / DevEx — teams evaluating the SDK that already run Postgres (Supabase),
  MySQL, or MongoDB for their app data must currently stand up a *second* datastore just for
  auth. That's adoption friction plus an extra piece of infra to operate.
- **The real work is not the adapters.** Each adapter is ~120 lines. The work is §3 — the
  atomicity, expiry, collation, and isolation requirements that a reasonable engineer
  implementing `StorageAdapter` against SQL **will get wrong on the first try**, in ways that
  produce permanent rate-limit lockouts, sessions that outlive their TTL, and (on Supabase)
  publicly-readable session tokens. Those requirements are currently written down nowhere.
- **Verification (planned):** a shared, framework-agnostic **conformance suite** (§7) run
  against every first-party adapter in CI, with the §3 hazards as explicit failing-by-default
  cases. `tsc --noEmit` + Prettier clean, full Jest suite green. SQL/Mongo adapters get
  dockerized integration tests against **real** Postgres/MySQL/Mongo containers — their
  atomicity and collation guarantees are properties of the engine and cannot be verified
  against a hand-rolled mock.

---

## 1. Current state — the seam already exists, unguarded

The server layer never imports a database client. `AuthHandlerOptions` takes an injected
`storage: StorageAdapter` ([`src/server/routes.ts:21-24`](../src/server/routes.ts#L21-L24)),
and every handler goes through that interface exclusively
([`session.ts`](../src/server/session.ts), [`challenge.ts`](../src/server/challenge.ts),
[`rateLimit.ts`](../src/server/rateLimit.ts)). `StorageAdapter` is deliberately storage-shaped,
not Redis-shaped ([`src/storage/adapter.ts`](../src/storage/adapter.ts)).

So a developer **can already** pass `createNextAuthRoutes({ storage: anything })` — the four
first-party adapters (`RedisAdapter`, `VercelKVAdapter`, `UpstashAdapter`, `MemoryAdapter`) are
just the implementations that happen to exist. What's missing isn't capability; it's every
guardrail around the capability:

| Gap | Today | This PRD |
|---|---|---|
| First-party SQL/document adapters | none — Redis family only | Postgres + SQLite (Phase 1), Mongo (Phase 2) — §5 |
| The correctness contract | **nowhere** — the interface's doc comments describe *what* each method does, never the atomicity/expiry invariants callers silently depend on | §3, plus expanded in-code contract docs on `adapter.ts` |
| Correctness verification for a custom adapter | none | exported conformance suite; §3's hazards are its test cases — §7 |
| Auto-detection | Redis/Upstash/KV env vars only ([`resolve.ts:28-52`](../src/storage/resolve.ts#L28-L52)) | scheme-dispatched `DATABASE_URL`, explicit precedence, throw-on-ambiguity — §6 |
| Per-backend multi-tenancy (`appId`) | n/a | **none needed** — see below |

**Why no adapter needs to know `appId` exists:** every key reaching an adapter is already a
fully-opaque string assembled by the caller, and the adapter's job is to store bytes under it.
Multi-tenancy is inherited for free: the `':'`-exclusion validation on `appId` that prevents
namespace escape happens upstream, before the key is built
([`routes.ts:46`](../src/server/routes.ts#L46)). A SQL adapter stores the key string in a
primary-key column; Mongo uses it as `_id`. **No adapter may parse, split, or interpret a key.**
It is an opaque byte string. (Corollary for §3.2 and §3.7: it is also *attacker-influenced*.)

Two details here are load-bearing for the sections below, and both are easy to get wrong because
the obvious generalization is false:

- **Not every key is app-scoped.** Three of the four keyspaces are, via `appScoped()`
  ([`src/server/keys.ts`](../src/server/keys.ts)) — `pubKey:`, `challenge:`, `session:`. The
  **email index is deliberately not**: its key is the bare `email:{address}`, built in
  [`session.ts:63-65`](../src/server/session.ts#L63-L65), with the `appId` carried as a *hash
  field* instead. That is the whole point of the hash (§3.4), and it means an adapter's hash
  keyspace is the one place where a **tenant identifier is data, not namespace** — see §3.4
  (Mongo) and §3.5 (collation), where that distinction turns into a cross-tenant bug.
- **`appId` may contain a dot.** The regex is `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and the
  documented, *recommended* form is a domain — `"myapp.example"`
  ([`config.ts:66`](../src/core/config.ts#L66)). Any adapter that puts a hash field into a
  **dotted path** (the natural Mongo `$set: {"fields." + field}`) is therefore broken by the
  recommended configuration, not by an exotic one. §3.4.

## 2. Goals / non-goals

**Goals**
- Point the SDK at Postgres, SQLite, or Mongo with the same one-line ergonomics Redis has.
- Give anyone running something else (DynamoDB, Firestore, Couchbase, homegrown) a written
  contract **and an executable test kit** to self-certify a custom adapter.
- Leave existing Redis/Upstash/Vercel KV deployments bit-for-bit unaffected.

**Non-goals**
- No ORM/query-builder coupling (Prisma, Drizzle) — adapters talk to raw drivers (`pg`,
  `mysql2`, `mongodb`), the same low-level posture as `ioredis` today.
- No migration tooling beyond a `schema.sql` the developer runs once.
- No change to *what* is stored (opaque JSON blobs + hash fields). Transport/backend only.
- **Explicitly not** a "SQL-native schema" — no `users` table with typed columns. The
  KV shape is what makes the adapter surface small enough to be verifiable. A relational
  redesign is a different, breaking PRD.

## 3. The correctness contract — what a new backend must actually guarantee

This is the core of the PRD. `MemoryAdapter` ([`src/storage/memory.ts`](../src/storage/memory.ts))
is the **normative reference implementation**: it is small, in-tree, and already encodes every
invariant below. When this document and `MemoryAdapter` disagree, `MemoryAdapter` (matching real
Redis) is right and this document is a bug.

Each hazard below is a **required conformance-suite case** (§7).

### 3.1 The three expiry invariants (get these wrong → permanent user lockout)

Redis gives `SET ... EX`, `INCR`, and `EXPIRE` semantics that callers depend on **implicitly**.
Written out:

> **(a) An expired key is indistinguishable from an absent key**, on every read path.
> **(b) `incr` on an expired key returns `1`** — it starts a fresh counter and drops the stale TTL.
> **(c) `incr` on a live key preserves that key's existing TTL** — it never extends or clears it.
> **(d) `expire` on an absent or expired key is a no-op** — it must never resurrect or create a row.

**Why (b) is load-bearing — the permanent-lockout bug.** `checkRateLimit` infers "this is the
first hit of a new window" from `count === 1`, and only then stamps the TTL
([`rateLimit.ts:21-31`](../src/server/rateLimit.ts#L21-L31)). Now consider the obvious SQL
`incr` — `INSERT … ON CONFLICT (key) DO UPDATE SET value = value + 1 RETURNING value` — against
a row whose `expires_at` is in the past:

1. Stale row holds `value = 15`, long expired. Upsert increments it → returns `16`, not `1`.
2. `16 !== 1`, so the new window's TTL is never stamped. `16 > maxAttempts` → the self-heal
   branch fires `expire(key, windowSeconds)`, refreshing `expires_at`.
3. `allowed: false`. The row is now live again, still at 16, and every subsequent request
   repeats step 2.

That identifier — an IP, an email, or a public key — is rate-limited **forever**. It is a
self-inflicted, permanent denial of service, and it will not show up in any smoke test, because
it only manifests after a window elapses under sustained traffic. The correct upsert folds the
expiry check into the `DO UPDATE`:

```sql
INSERT INTO ttc_kv (key, value, expires_at) VALUES ($1, '1', NULL)
ON CONFLICT (key) DO UPDATE SET
  -- expired row => start a fresh counter at 1 (invariant b); else increment (c)
  value = CASE WHEN ttc_kv.expires_at IS NOT NULL AND ttc_kv.expires_at <= $2
               THEN '1' ELSE (ttc_kv.value::bigint + 1)::text END,
  -- and drop the stale TTL, but otherwise leave a live TTL untouched (invariant c)
  expires_at = CASE WHEN ttc_kv.expires_at IS NOT NULL AND ttc_kv.expires_at <= $2
                    THEN NULL ELSE ttc_kv.expires_at END
RETURNING value;
```

One statement, engine-enforced atomicity, no read-modify-write, no app-level transaction.
`MemoryAdapter.incr` does exactly this via `alive()`, which self-deletes the expired entry
before the increment.

**Why (d) matters:** `expire` implemented as an upsert would *create* a rate-limit row for a key
that was never `incr`'d, and would resurrect expired sessions. Use `UPDATE … WHERE key = $1 AND
(expires_at IS NULL OR expires_at > $now)`.

### 3.2 Expiry must be enforced on **read**, not delegated to a background reaper

`consumeChallenge` accepts any non-null value `getdel` hands back
([`challenge.ts:35-37`](../src/server/challenge.ts#L35-L37)). `verifySession` accepts any
non-null value `get` hands back ([`session.ts:110-111`](../src/server/session.ts#L110-L111)).
**Neither performs an independent expiry check** — both delegate expiry entirely to the storage
layer. That is fine against Redis, whose expiry is exact.

It is **not** fine against a backend whose expiry is a *background sweep*. MongoDB's TTL index
(`expireAfterSeconds`) is swept by a monitor that runs **roughly every 60 seconds**, and deletion
is best-effort under load. A challenge or a session bearer token therefore remains **readable —
and accepted — for up to a minute past its stated TTL**, silently extending the exposure window
of a leaked token. The same applies to any cron/`pg_cron`-based reaper.

> **Requirement:** every adapter enforces expiry in the read path itself
> (`WHERE expires_at IS NULL OR expires_at > $now`, or the Mongo filter equivalent). A TTL index
> or reaper job is a **space-reclamation optimization only** and is never the expiry authority.
> Mongo adapters MUST store an explicit `expiresAt` and filter on it, *in addition to* the TTL
> index.

### 3.3 Lazy expiry alone leaks storage — a reaper is still required (for space)

The flip side of §3.2. Read-path expiry makes an expired row *invisible*, but never *deletes* it
unless something reads it again — and rate-limit rows, abandoned challenges, and expired sessions
are typically **never read again**. Redis reclaims this automatically; SQL does not. A busy
deployment accumulates dead rows indefinitely: one per (endpoint, appId, IP) per window, forever.

So both halves are needed, and they solve different problems:

| Mechanism | Solves | Authoritative? |
|---|---|---|
| Read-path `expires_at` filter (§3.2) | **correctness** — expired ⇒ invisible, exactly on time | **yes** |
| Reaper / TTL index (this section) | **space** — bounded table growth | no |

Ship the reaper as a new **optional** interface method, feature-detected by callers, so no
existing adapter is invalidated (§8):

```ts
/** OPTIONAL. Delete expired rows. Space reclamation only — never the expiry authority (§3.2).
 *  Returns the number of rows removed. Adapters with native expiry (Redis/KV) omit it. */
sweepExpired?(limit?: number): Promise<number>;
```

Backed by a partial index (`CREATE INDEX … ON ttc_kv (expires_at) WHERE expires_at IS NOT NULL`),
plus documented wiring: a `pg_cron` job, a platform cron route, or an opportunistic probabilistic
sweep. **The Mongo TTL index is precisely this** — a reaper — which is why §3.2 still requires the
explicit read filter alongside it.

### 3.4 `hset` must be a per-field atomic write, never read-modify-write

The email→`{appId: publicKey}` index is a hash **specifically** so two concurrent registrations of
the same email under different `appId`s cannot lose a write — see the warning on the interface
itself ([`adapter.ts:21-26`](../src/storage/adapter.ts#L21-L26)). A SQL implementation that stores
the hash as one JSON blob and does `SELECT → merge field → UPDATE` **reintroduces exactly the race
the hash design was built to eliminate.** The hash gets its own table, keyed `(key, field)`:

**Postgres / SQLite** (both deterministic + `NO PAD` by default, so `VARCHAR` is safe here — MySQL
is **not**, and substitutes `VARBINARY(512)` / `VARBINARY(128)` for every key and field column, and
`MEDIUMTEXT` for `value`. See §3.5 and §3.6; this difference is not cosmetic, it is the whole
reason MySQL is Phase 3):

```sql
CREATE TABLE IF NOT EXISTS ttc_kv (
  key        VARCHAR(512) PRIMARY KEY,   -- §3.5 (binary, non-padding) + §3.6 (worst case 404 B)
  value      TEXT NOT NULL,              -- §3.6 (a 64-wallet UserData is ~15 KB)
  expires_at BIGINT                      -- epoch ms; NULL = no expiry. §3.2 filters on READ.
);
CREATE TABLE IF NOT EXISTS ttc_kv_hash (
  key   VARCHAR(512) NOT NULL,
  field VARCHAR(128) NOT NULL,           -- appId, bounded to 64 by APP_ID_RE — may contain '.'
  value TEXT NOT NULL,
  PRIMARY KEY (key, field)               -- per-field atomicity lives here. No expires_at (§3.11).
);
CREATE INDEX IF NOT EXISTS ttc_kv_expires_idx ON ttc_kv (expires_at) WHERE expires_at IS NOT NULL;
```

`hset` is then one statement: `INSERT … ON CONFLICT (key, field) DO UPDATE SET value = excluded.value`
(Postgres/SQLite) / `ON DUPLICATE KEY UPDATE value = VALUES(value)` (MySQL).

**The hash table has no `expires_at` by design** — the email index is permanent, as
`MemoryAdapter` notes. Do not add TTL to it. (Which makes it the one unbounded-growth surface in
the schema — see §3.11.)

**Mongo must NOT model the hash as fields of a subdocument.** The obvious encoding —
`updateOne({_id: key}, {$set: {["fields." + field]: value}}, {upsert: true})` — is **broken by the
SDK's own recommended configuration.** The hash field is an `appId`, the `appId` regex permits
`.`, and the documented recommended value is a domain like `"myapp.example"`
([`config.ts:66`](../src/core/config.ts#L66)). Mongo interprets `.` in an update path as
*nesting*, so:

- `hset("email:a@b.com", "myapp.example", pk)` writes `{fields: {myapp: {example: pk}}}` — a
  nested document, not a field named `myapp.example`.
- `hgetall` then returns `{myapp: {example: pk}}`, which **violates the declared
  `Record<string, string>`** return type. (Unobservable today only because no caller invokes
  `hgetall` — but it is in the public interface, in the conformance suite, and in every
  third-party adapter's contract.)
- Worst: a second tenant whose `appId` is the **prefix** of the first (`myapp` alongside
  `myapp.example`) collides in the nesting. Depending on write order, one silently **destroys**
  the other's index entry, or `hset` hard-errors (`Cannot create field 'example' in element
  {myapp: "…"}`) and **registration fails**. That is cross-tenant data loss driven purely by
  tenant *naming*.

> **Requirement:** the Mongo adapter gives the hash its **own collection**, mirroring the SQL
> two-table design — `ttc_kv_hash` with a compound unique index on `{key: 1, field: 1}`, and
> `key`/`field` passed only as **scalar string values in a filter**, never as a path or a key of
> an update document:
>
> ```js
> await hash.updateOne({ key, field }, { $set: { value } }, { upsert: true });   // hset
> await hash.findOne({ key, field });                                            // hget
> await hash.find({ key }).limit(HGETALL_MAX).toArray();                         // hgetall (§3.11)
> ```
>
> This sidesteps `.`/`$` in field names entirely (§3.7), keeps `hset` a single atomic upsert
> (the per-field atomicity this section exists to protect), and keeps the adapter honest about
> never interpreting a key. Create the unique index at `ensureIndexes()` time — without it, the
> `upsert` races two concurrent registrations into duplicate rows, which is precisely the lost
> write this whole section is about.

### 3.5 Collation must be **binary and non-padding** — the default collation corrupts the keyspace

Keys embed **base58 Solana public keys** and hex, which are **case-sensitive**. MySQL's default
collation (`utf8mb4_0900_ai_ci` / `utf8mb4_general_ci`) is **case-insensitive and
accent-insensitive**. Under it, two *distinct* Solana addresses differing only in case map to the
**same primary-key row** — one user's `UserData` record silently overwrites or is returned for
another's. That is a cross-account data-integrity failure and a potential account-takeover
primitive, from a default nobody would think to override.

The same default is **also a cross-tenant** failure, not just cross-account, and that is the worse
half: `appId` is the hash **field** in the email index (§3.4) and a namespace segment in every
other key. Under a case-insensitive collation, tenants `Acme` and `acme` are the **same
namespace** — one app reads and overwrites the other's records. An `allowedAppIds` allowlist does
not save you: both spellings can legitimately be on it.

**Binary collation is necessary but *not sufficient* on MySQL — this is the subtle part.** MySQL
collations carry a *pad attribute*, and `utf8mb4_bin` is **`PAD SPACE`**: it compares strings
**ignoring trailing spaces**, so `'k'` and `'k '` are **equal**, including for `PRIMARY KEY`
uniqueness. A binary-but-padding collation therefore still collapses two distinct keys into one
row. (Only the UCA-9.0.0 collations — `utf8mb4_0900_bin`, `utf8mb4_0900_as_cs` — are `NO PAD`.)

Today no key can carry a trailing space: the validators exclude whitespace (`EMAIL_RE`,
`APP_ID_RE`) and `emailKey()` calls `.trim()` — so this is **latent, not live**. It is called out
anyway because the requirement as originally written (`utf8mb4_bin`) is simply *wrong*, the
correct version costs nothing, and "no key will ever have a trailing byte the collation ignores"
is exactly the kind of invariant that quietly dies the first time someone adds a field.

> **Requirement:** all key/field columns are **binary and non-padding**. On MySQL use
> **`VARBINARY(512)`** (byte-wise, no pad semantics) — or, if a character type is required,
> `CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin` (MySQL ≥ 8.0.1). **Do not use
> `utf8mb4_bin`.** Postgres (`C`/deterministic default) and SQLite (`BINARY` default) are correct
> out of the box — but the SQLite adapter must never declare a column `COLLATE NOCASE`, and the
> Postgres adapter must reject a database created with a **nondeterministic** ICU collation
> (`SELECT collname FROM pg_collation WHERE NOT collisdeterministic` — a nondeterministic collation
> can equate distinct byte strings for uniqueness purposes exactly as `PAD SPACE` does).
> Conformance cases: `set("K","a")` / `set("k","b")` are two independent keys, **and**
> `set("k","a")` / `set("k ","b")` are two independent keys.

### 3.6 Column sizing — silent truncation corrupts `UserData` into an unrecoverable account

- **Keys** are longer than they look. Worst case is a rate-limit key built from an email:
  `ratelimit:` (10) + `register:` (9) + `appId` (≤64, per `APP_ID_RE`) + `:` (1) + the **email
  address** — which `validateEmail` bounds at **320**, not the 254 of RFC folklore
  ([`routes.ts:49`](../src/server/routes.ts#L49)). Worst case is therefore **404 bytes**, not the
  ~340 a 254-char email would suggest. **Size keys at 512** — which holds, but with ~100 bytes of
  headroom, not 170. Anyone "optimizing" to `VARCHAR(384)` off the folklore number lands *inside*
  the reachable range and silently truncates. Session keys are far shorter (`session:` + appId +
  64-hex token). (512 bytes is well within InnoDB's 3072-byte `DYNAMIC` index limit, and the
  composite `(key, field)` PK at 512+128 also fits.)
  **This bound is only real if every key substring is validated first — and on one path it isn't
  today. See §3.9.**
- **Over-length keys must be rejected, never truncated.** Whatever the column width, an adapter
  handed a key longer than it can store must **throw**. A truncating write is worse than a failing
  one in every direction: two distinct keys silently become one row (the §3.5 collision, by
  another route), and a truncated *session* key would be a cross-account read. Postgres and
  SQLite (with `STRICT` tables) error by default; MySQL is the outlier — see below.
- **Values:** a `UserData` blob holds up to `maxWalletsPerUser` = **64** encrypted wallets
  ([`config.ts:150-151`](../src/core/config.ts#L150-L151)), each ~230 bytes of JSON → **~15 KB**,
  and that is the *documented cap*, not a worst case with future fields. MySQL's `TEXT` tops out
  at 65,535 **bytes** — and MySQL in non-strict mode **truncates silently rather than erroring**.
  A truncated blob is invalid JSON, so `getUserByPublicKey`'s `JSON.parse` throws and its
  `catch` returns `null` ([`session.ts:47-51`](../src/server/session.ts#L47-L51)) — the record
  fails *safe*, but the user is **permanently locked out of every wallet in it**, with no error
  anywhere pointing at the database. Use `MEDIUMTEXT` on MySQL, assert `STRICT_ALL_TABLES`, and
  make "store a 64-wallet `UserData` and read it back byte-identical" a conformance case.

### 3.7 Injection safety is a hard requirement, not a recommendation

Keys and values carry attacker-influenced substrings (email addresses, public keys, and an
`appId` that may come straight off the request — [`config.ts:76-82`](../src/core/config.ts#L76-L82)).
No adapter may interpolate a key, field, or value into a query string. SQL adapters use
parameterized queries exclusively.

The Mongo adapter has the subtler job, because Mongo's injection surface is **structural**, not
lexical — there is no query string to escape, so the classic defense doesn't apply and the danger
looks like ordinary code:

- Pass `key`/`field` only as **scalar string values** inside a filter — `{ key, field }` — never as
  a filter *object* (`{ key: someParsedJson }` lets an attacker-supplied `{"$gt": ""}` become an
  **operator** and match every row), never as a **key** of an update document, and never anywhere
  near `$where` or `$expr`.
- Never build an update **path** from a key or field. This is what §3.4 resolves: `"fields." + field`
  is string interpolation into a query language, wearing the costume of a JS expression — and with a
  dot-containing `appId` it silently reshapes the document. The separate-collection design in §3.4
  exists precisely so that `$`/`.` in a field are inert data rather than syntax.
- If any body value ever reaches an adapter unparsed, `JSON.parse` must not be trusted to yield a
  string: assert `typeof key === "string"` at the adapter boundary. `{"$ne": null}` arriving where a
  string was expected is the entire NoSQL-injection genre.

Conformance feeds SQL-shaped (`' OR 1=1 --`), NoSQL-operator-shaped (`{"$gt":""}`, `{"$ne":null}`),
and `$`/`.`-containing keys and fields through **every** method and asserts they round-trip as inert
data — the dotted-`appId` case (§3.4) is the one that catches the realistic bug.

### 3.8 `del` semantics across the two keyspaces — an ambiguity to resolve now

Real Redis `DEL` removes a key of **any** type. `RedisAdapter` inherits that.
`MemoryAdapter.del` deletes only from its string map, never `hstore`. **These already disagree.**
It is unobservable today (no caller ever `del`s an email-index key), but a two-table SQL adapter
forces the question — does `del` touch `ttc_kv_hash`?

> **Resolution:** specify Redis semantics — `del` removes the key from **both** keyspaces — and
> fix `MemoryAdapter.del` accordingly (a 1-line change; no caller depends on the current
> behavior, so it is non-breaking). This is the conformance suite paying for itself before a
> single new adapter is written.

### 3.9 Every substring of a key must be length-bounded *before* it reaches the adapter 🚨

§3.6 sizes the key column at 512 by deriving a worst case from the validators. That derivation is
only sound if the validators actually run on every path that builds a key. **On the email-login
path, one does not.**

`POST /login` (email) checks only that `body.email` is *present*, then feeds it straight into two
storage keys — the email-index lookup (`resolvePublicKeyByEmail` → `email:{address}`) and the
rate-limit counter (`` `login:${appId}:${body.email}` ``) — with **no `validateEmail` call**
([`routes.ts:313-341`](../src/server/routes.ts#L313-L341)). Contrast `/register`, which validates
first ([`routes.ts:234-252`](../src/server/routes.ts#L234-L252)). So an unauthenticated caller can
submit a **1 MB `email`** and have it become a storage key.

Against Redis this is inert — keys are effectively unbounded and the lookup simply misses. Against
the backends this PRD adds, it stops being inert:

| Backend | Result of a 1 MB key |
|---|---|
| Postgres | `22001 value too long` → the query throws → **unauthenticated 500 + error-log flood** |
| MySQL (non-strict) | **silent truncation to 512** → every long email collapses onto one rate-limit row, sharing a bucket |
| Mongo | `_id` over the 1024-byte index-key limit → write error |

None of these is an authentication bypass — `/login` still requires a valid ed25519 signature over
a consumed challenge, so a truncated or collided *read* yields a record the caller cannot
authenticate as. The impact is availability and hygiene, not takeover. But it invalidates §3.6's
column-sizing premise, and it is the exact shape of bug that becomes a takeover the moment someone
adds a keyed write to that path.

> **Requirement (two independent layers, because either alone is a single point of failure):**
> 1. **Caller side —** `/login` validates `body.email` before the first key is built, exactly as
>    `/register` does. Three lines in `routes.ts`. This is a **prerequisite** for the SQL adapters,
>    not a follow-up.
> 2. **Adapter side —** every adapter rejects a key longer than its column (§3.6) by **throwing**.
>    An adapter must never assume its caller validated anything; it is a public interface that
>    third parties implement against.
>
> **Contract statement for `adapter.ts`:** *keys are opaque, but they are also
> attacker-influenced and bounded. An adapter that silently accepts a key it cannot store
> losslessly is non-conformant.*

### 3.10 Storage failures must fail **closed**

`checkRateLimit` has no `try`/`catch`: if `incr` throws, the exception propagates out of the route
and the request 500s. That is the **correct** behavior — a rate limiter that cannot count must not
grant permission — and it is a property of the *caller*, which the new adapters must not quietly
undo.

The temptation is specific and predictable. A pooled SQL adapter fails in ways an in-process Redis
client mostly doesn't (pool exhaustion, connection reset, failover), so the natural defensive
reflex is a `catch` that returns a benign default: `incr` → `0`, `get` → `null`, `hget` → `null`.
Every one of those is a **security control silently switching off**:

| Swallowed error | What actually happens |
|---|---|
| `incr` returns `0`/`1` on failure | `count <= maxAttempts` ⇒ **rate limiting is disabled**, silently, under exactly the load that caused the failure |
| `getdel` returns `null` on failure | challenge consumption fails closed — safe, but a transient DB blip becomes a login failure with no diagnostic |
| `set` swallows a write failure | `issueSession` returns a token that was **never stored** ⇒ every subsequent request 401s |

> **Requirement:** adapters **propagate** storage errors. They do not catch-and-default, and they
> do not translate a failed write into a resolved promise. `null` is reserved for *"the backend
> answered, and the key is absent"* — never for *"the backend did not answer."* Retries (bounded,
> for transient connection errors) are permitted; converting an error into a value is not.

### 3.11 `hgetall` is the one unbounded read — bound it

The hash table has no TTL (§3.4) and no reaper (§3.3): the email index is **permanent by design**.
Its cardinality is "one field per `appId` this email has registered under" — which is small and
safe *if* `appId` is a closed set, and unbounded if it is not. `allowedAppIds` is **optional**, and
when it is unset the SDK accepts any well-formed `appId`
([`config.ts:76-82`](../src/core/config.ts#L76-L82), which already flags the storage-bloat risk).

So an attacker who can register can mint 10 000 namespaces against one victim email and grow that
one hash without bound, forever. On Redis, `HGETALL` on a large hash is a latency problem. On SQL
it is `SELECT … WHERE key = $1` with **no `LIMIT`** — an unbounded result set marshalled into a
`Record<string, string>` in the server's heap.

> **Requirement:** `hgetall` reads with an explicit cap (`LIMIT`), and the adapter **throws or
> logs loudly** when the cap is hit rather than returning a silently-partial hash — a truncated
> email index is a wrong answer, not a small one. And the docs promote `allowedAppIds` from
> "STRONGLY recommended" to **required** for any deployment sharing one database across apps,
> because it is the only bound on the one table nothing ever reclaims.

## 4. Backend, deployment, and data-at-rest hazards

### 4.1 Supabase — a `public`-schema table is exposed on the internet by default 🚨

Supabase auto-generates a **PostgREST API over every table in the `public` schema** and serves it
to anyone holding the `anon` key — which is, by design, shipped to browsers. A table created with
the obvious `CREATE TABLE ttc_kv (…)` and no Row Level Security is therefore **world-readable**.

`ttc_kv` contains **session bearer tokens** (`session:{appId}:{token}` → `publicKey`) and every
user's **encrypted wallet blob**. A world-readable `ttc_kv` is full, silent account takeover for
every user of the deployment, plus an offline attack corpus of wallet ciphertext. This is the
single highest-severity failure mode in this PRD, it is reachable by following the *most natural*
setup path, and it is invisible from the application side — everything works perfectly.

Note the asymmetry in what leaks, because it is what §4.6 is built on: the **wallet blobs are
client-side-encrypted** — an attacker gets ciphertext and must go offline against PBKDF2 (600k
iterations at the default security level). The **session tokens are not**. They are live bearer
credentials sitting in a column, usable immediately, with no cracking step. The tokens are the
crown jewel here, and they are the part this PRD can actually take off the table — **§4.6**.

> **Requirement — the Supabase schema.sql creates the tables in a dedicated, non-exposed schema
> and enables RLS regardless (defense in depth; the SDK connects as the owner/`service_role`,
> which bypasses RLS by design):**
>
> ```sql
> CREATE SCHEMA IF NOT EXISTS tetrac;              -- NOT `public` => not exposed by PostgREST
> REVOKE ALL ON SCHEMA tetrac FROM anon, authenticated;
> -- …tables from §3.4, created in `tetrac.` …
> ALTER TABLE tetrac.ttc_kv      ENABLE ROW LEVEL SECURITY;  -- deny-by-default: no policies
> ALTER TABLE tetrac.ttc_kv_hash ENABLE ROW LEVEL SECURITY;
> ```
>
> Ship this as `supabase.sql`, separate from the generic `postgres.sql`, and lead the Supabase
> docs with the exposure warning rather than burying it in a note. Add a **startup assertion** to
> `PostgresAdapter`: if the tables resolve to the `public` schema on a host matching
> `*.supabase.co`, log a loud warning (one line, at construction) naming the exposure.

Also for Supabase: the **transaction-mode connection pooler** (port `6543`) does not support
session-level state or named prepared statements. Either connect direct (`5432`) from a
long-lived server, or use the pooler with prepared statements disabled — and prefer
`@supabase/supabase-js`'s Postgres connection or `@vercel/postgres`/`@neondatabase/serverless`
(both structurally compatible with `PostgresLike`) from serverless/edge runtimes.

### 4.2 Serverless connection pooling

Redis/KV clients are cheap to construct per-invocation. Pooled SQL/Mongo clients are not — a
`new pg.Pool()` per request exhausts the server's connection limit under concurrency, and the
failure mode is a hard outage, not degradation. Docs must state, per backend: **module-level
singleton** client (warm invocations reuse the module); a serverless-native driver
(`@neondatabase/serverless`, `@vercel/postgres`, PlanetScale's for MySQL) for edge runtimes where
raw TCP pooling is unavailable; and for Mongo, that the official driver pools correctly across
warm invocations *provided* the client is a module-level singleton.

### 4.3 SQLite is dev / self-host / single-instance only

A local file cannot be shared across serverless instances or horizontally-scaled replicas — the
same caveat the existing dev-only `redis://localhost:6379` fallback already carries
([`resolve.ts:10`](../src/storage/resolve.ts#L10)). `better-sqlite3` is also **synchronous**: it
blocks the event loop for the duration of each query, which is fine at dev/self-host scale and
not fine under load. Enable WAL + a `busy_timeout`, and flag the constraint prominently — not in
a footnote.

**And the file itself is a credential store on disk — treat it like one.** This is the hazard the
Redis backends never had, because Redis was never a file:

- **Mode `0600`, owner-only.** SQLite creates the database world-readable (`0644`, minus umask).
  On any shared or multi-tenant host, every local user can then read **session tokens and wallet
  ciphertext**. The adapter sets the mode explicitly at creation and does not rely on umask.
- **Never inside a web-served directory.** A `sqlite.db` (or `data.db`, or `ttc.sqlite`) written
  under `public/`, `static/`, or any path a framework serves verbatim is a **one-request download
  of the entire auth store** — no vulnerability required, just a URL. The adapter must refuse a
  path under a known-served directory, or at minimum log a startup error naming the risk.
  A world-readable `public/ttc.sqlite` is §4.1's Supabase failure with a different spelling, and
  it arrives by the same route: the most convenient place to put the file.
- **The sidecars leak too.** WAL mode creates `-wal` and `-shm` alongside the database, containing
  recently-written pages — i.e. the newest session tokens. Locking down the `.db` file and
  ignoring `.db-wal` protects nothing. Same directory, same mode, same exclusion rules.
- **Back it up like a secret**, not like a config file: it is the only backend where the operator's
  natural instinct is to `scp` the store around or drop it in the repo. `.gitignore` it in the
  template.

### 4.4 MySQL has no `DELETE … RETURNING`

`getdel` **must** be atomic — it is the sole mechanism closing the challenge-replay race
([`challenge.ts:22-26`](../src/server/challenge.ts#L22-L26)). Postgres and SQLite (≥3.35) express
it as one `DELETE … RETURNING value`. MySQL cannot, and needs an explicit transaction
(`SELECT … FOR UPDATE` then `DELETE`). Getting this wrong turns a single-use challenge into a
replayable one — this is why MySQL is Phase 3 rather than Phase 1, and why its conformance run
includes a concurrent-`getdel` case asserting exactly one caller observes the value.

### 4.5 Operational hygiene

Postgres runs `ON CONFLICT` upserts correctly under `READ COMMITTED` (the default); under
`REPEATABLE READ`/`SERIALIZABLE` they can raise serialization failures — document the expectation
rather than silently depending on it. Driver **query logging must not log parameters** (§4.8).
`better-sqlite3` (native) and often `pg` must be listed in Next.js `serverExternalPackages`, or
the bundler will try to bundle them and fail at build.

### 4.6 Hash the session token before it becomes a key 🚨 — the highest-leverage change here

Everything above hardens the *container*. This hardens the *contents*, and it is the one change
that degrades gracefully when the container fails anyway.

The raw bearer token is written to storage in **two** places, and both must change together or the
fix is theatre:

1. **The session key** — `session:{appId}:{token}` → `publicKey`
   ([`session.ts:129-131`](../src/server/session.ts#L129-L131)).
2. **Inside the `UserData` blob** — `issueSession` does `user.authToken = token` and persists the
   record ([`session.ts:90-91`](../src/server/session.ts#L90-L91)), so the same raw token also sits
   in the `pubKey:{appId}:{publicKey}` value as a plain JSON field
   ([`types.ts:68`](../src/core/types.ts#L68)).

> ⚠️ **An earlier draft of this section proposed hashing the session *key* only. That would have
> been a false fix** — the raw token would still be readable in every `UserData` blob, so a
> world-readable table still hands the attacker a live credential for every logged-in user. Hashing
> one of the two locations achieves nothing. Both, or neither.

The token in those columns **is** the credential. Anyone who can read the table — via §4.1's
PostgREST exposure, a backup, a read replica, an analytics sync, a `SELECT` from unrelated app code
sharing the connection, a slow-query log (§4.8), or a `.db` file in `public/` (§4.3) — can replay it
directly. No cracking, no escalation. That was an acceptable posture when the store was Redis:
ephemeral, in-memory, one process, nobody's BI tool pointed at it. **It is not the posture of a
Postgres database**, which is backed up nightly, replicated, dumped to staging, and read by every
service with the same DSN.

The token is `randomHex(32)` — **256 bits of CSPRNG entropy**
([`crypto.ts:109-111`](../src/core/crypto.ts#L109-L111)). That means it needs no KDF, no salt, and
no stretching: there is no dictionary to attack and no precomputation that helps against a uniform
2²⁵⁶ space. A **plain SHA-256** is a preimage-resistant index over it — the same construction
GitHub uses for PATs and every well-built API-key store uses for keys.

> **Requirement:** storage sees the **digest**, never the token — in **both** locations.
>
> ```ts
> // src/core/crypto.ts — next to the existing hashUserAgent(), same primitives, ~3 lines
> export function hashSessionToken(token: string): string {
>   return bytesToHex(sha256(utf8ToBytes(token)));
> }
>
> // src/core/types.ts — UserData
> - authToken: string;        // the raw bearer token
> + authTokenHash?: string;   // SHA-256 of it. Used to revoke the previous session on re-login.
>
> // src/server/session.ts — (1) the key
> function sessionKey(appId: string, token: string, config: AuthConfig): string {
>   return appScoped(config.keyPrefixes.session, appId, hashSessionToken(token));
> }
> // …and (2) the record: store the hash, and pass the raw token out explicitly rather than
> // smuggling it to the response via `user.authToken` (which is what asResult() reads today).
> ```
>
> The raw token is returned to the client and **never persisted server-side**. `verifySession` and
> `revokeSession` already funnel through `sessionKey()`, so they need no change at all; the lookup
> stays O(1) — still a primary-key hit, just on a digest. The client contract
> (`AuthResult.authToken`, `localStorage`, the `ttc-auth-token` header) is **untouched**.
>
> Full implementation, migration, and the `asResult(user, token)` refactor: **[`PRD/v0.5.0-PRD.md`
> §1](../PRD/v0.5.0-PRD.md)** — this lands in `0.5.0`, *before* any SQL adapter exists.

What this buys, concretely: **§4.1's catastrophe stops being a catastrophe.** A world-readable
`ttc_kv` then leaks encrypted wallet blobs (already ciphertext, already behind 600k PBKDF2
iterations) and a column of **64-hex digests that cannot be replayed as bearer tokens**. The
attacker learns *that* a session exists and which `publicKey` owns it. They cannot become that
user. That converts the highest-severity finding in this document from *silent, total, immediate
account takeover* into *a metadata leak* — and it does so for every leak channel at once (§4.3,
§4.7, §4.8, plus every backup and replica), rather than plugging them one at a time.

**Costs, stated plainly:**
- It touches `src/server/session.ts` + `src/core/crypto.ts`, so the "adapters only" framing of this
  PRD no longer strictly holds. That is why it is scoped as its own decision (§10).
- On upgrade, existing session keys no longer resolve ⇒ **every user is logged out once.** Session
  TTL is 4h and each login already revokes the prior token, so this self-heals within one TTL and
  costs a re-login. No data migration, no backfill, no dual-read window — the old rows simply
  expire. (If even that is unacceptable, a dual-read fallback for one TTL is possible, but it keeps
  the raw tokens readable for that window and is not worth it.)
- It is **not** a substitute for §4.1's schema/RLS work. It is the layer that survives it failing.

> The same argument applies, more weakly, to the **challenge** key (`challenge:{appId}:{publicKey}`
> → challenge). There the *value* is the secret and the key is not, so hashing the key buys nothing;
> the challenge value is single-use, 5-minute-TTL, and useless without the wallet's private key.
> Leave it. This section is about the session token specifically, because it is the only stored
> value that is directly replayable as a credential.

### 4.7 Database privileges — least privilege, and RLS that actually applies

§4.1 enables RLS and then notes the SDK "connects as the owner/`service_role`, which bypasses RLS
by design." Both halves are true, and together they mean **the RLS line is decorative**: a table
owner bypasses RLS unless `FORCE ROW LEVEL SECURITY` is set, so the policy protects against exactly
nobody who is actually connecting. If RLS is going to be in the schema, make it bite.

The SDK needs four verbs on two tables. It does not need DDL, it does not need other schemas, and
it very much does not need `service_role` — a Supabase key that is a **global admin bypass over the
entire database**, whose compromise is not "the auth tables leak" but "every table you own leaks."
Using it as the SDK's connection identity means an SDK-side SSRF, log leak, or dependency
compromise escalates straight to full-database admin.

> **Requirement — the SDK connects as a dedicated, DML-only role:**
>
> ```sql
> CREATE SCHEMA IF NOT EXISTS tetrac;                    -- not `public` ⇒ not exposed by PostgREST
> REVOKE ALL ON SCHEMA tetrac FROM anon, authenticated;  -- belt: the Supabase browser roles
> -- …tables from §3.4, created in `tetrac.` …
>
> CREATE ROLE tetrac_app LOGIN PASSWORD :'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
> GRANT USAGE ON SCHEMA tetrac TO tetrac_app;
> GRANT SELECT, INSERT, UPDATE, DELETE ON tetrac.ttc_kv, tetrac.ttc_kv_hash TO tetrac_app;
> -- deliberately NOT granted: CREATE, TRUNCATE, REFERENCES, anything on any other schema.
>
> ALTER TABLE tetrac.ttc_kv      ENABLE ROW LEVEL SECURITY;   -- deny-by-default for every role…
> ALTER TABLE tetrac.ttc_kv_hash ENABLE ROW LEVEL SECURITY;
> CREATE POLICY sdk_all ON tetrac.ttc_kv      TO tetrac_app USING (true) WITH CHECK (true);
> CREATE POLICY sdk_all ON tetrac.ttc_kv_hash TO tetrac_app USING (true) WITH CHECK (true);
> -- …permitted for exactly one role. Now RLS is load-bearing, not cosmetic.
>
> ALTER ROLE tetrac_app SET search_path = tetrac, pg_catalog;   -- see below
> ```
>
> Note the ordering trap: RLS is **deny-by-default with no policies**, so enabling it on a table
> your DML role does not own — without the policy — locks the SDK out entirely and the app fails
> closed at startup. That is the correct failure, but it must be in the docs, or the first person
> to paste half this block will file a bug.

**Pin `search_path`.** The adapter should schema-qualify every statement (`tetrac.ttc_kv`), *and*
the role should have a pinned `search_path`. An unqualified `ttc_kv` resolves through
`search_path`, and if any schema earlier in that path is writable by another role, that role can
shadow the auth tables with its own — a table-hijack that redirects session writes to an
attacker-readable table. Schema-qualification alone is sufficient in principle; pinning as well
costs one line and removes the whole class.

**MySQL / Mongo equivalents:** a MySQL user granted `SELECT, INSERT, UPDATE, DELETE ON tetrac.*`
and nothing else (no `FILE`, no `SUPER`, no `PROCESS` — `PROCESS` exposes other sessions' running
statements, i.e. §4.8's leak by another name). A Mongo user with a **custom role** scoped to the
two collections in one database — not `readWrite` on `admin`, and never `root`.

### 4.8 The database's own logs are a token-exfiltration channel

§4.5 says the *driver* must not log parameters. The larger problem is that **the database logs
them for you**, by default, into places with a different (usually weaker) access model than the
table itself — and this is precisely where the §4.6 digest earns its keep, because it makes every
row below a non-event.

| Channel | What lands in it | Default |
|---|---|---|
| MySQL **general query log** / **slow query log** | full statements **with literal values** | slow log on in many managed tiers |
| MongoDB **database profiler** (`system.profile`) + `slowms` log lines | the full command **including the query filter** — i.e. the session key | profiler off; **slow-op logging on at 100 ms** |
| Postgres `log_statement` / `log_min_duration_statement` | statement text; bind params are logged in the `DETAIL` line **on error** | error case is on by default |
| Managed-DB "query insights" (RDS Performance Insights, Cloud SQL, Atlas) | sampled statements, retained for weeks, **exported to a different IAM boundary** | frequently on |
| APM / OpenTelemetry auto-instrumentation (`db.statement`) | statement, and with some integrations the params | on, if the app has APM |

A session key in a slow-query log is a **live credential in a log aggregator** — a system that is
typically read-only-to-many, retained for 30+ days, replicated to a SIEM, and *not* considered a
secrets store by anyone on the team. Note that Mongo's profiler is the sharpest edge: the filter
`{_id: "session:acme:<token>"}` is the whole credential, and the slow-op threshold that captures it
is on by default.

> **Requirement:** (a) disable parameter logging in the driver; (b) document, per backend, the
> server-side logs that must be off or scrubbed (`general_log=OFF`, profiler `level: 0`, no
> `log_statement=all`); (c) **treat this as unfixable-in-general and rely on §4.6** — you do not
> control the operator's managed-DB telemetry, their APM vendor, or their SIEM retention. A digest
> in a log line is inert. A token in a log line is an account.

**Also: never log the DSN.** `pg` and `mongodb` embed the connection string — *with the password* —
in some connection-error messages, and the natural `console.error(err)` at adapter construction
puts it straight into stdout, which on every serverless platform is a persisted, searchable log.
Adapters must redact credentials from any error they log or re-throw.

### 4.9 Transport security — `verify-full`, not `require`

`sslmode=require` **encrypts but does not authenticate**: it accepts any certificate, from anyone,
including an attacker who can answer for the DB host. It stops passive sniffing and does nothing
against an active MITM — who then sees every session token and wallet blob in cleartext. It is the
single most common Postgres misconfiguration and it reads like the secure option, which is why it
is worth spelling out rather than listing `sslmode=require` in a docs table as though it were the
answer.

> **Requirement, per backend:**
> - **Postgres:** `sslmode=verify-full` (verifies the cert chain **and** that the hostname matches),
>   with `sslrootcert` pointing at the provider's CA. `verify-ca` is a weaker fallback — it
>   validates the chain but not the hostname. Not `require`, not `prefer`, never `disable`.
> - **MySQL:** `ssl: { rejectUnauthorized: true, ca }` in `mysql2`. Setting `ssl: {}` alone does not
>   get you verification.
> - **Mongo:** `tls=true`, and **never** `tlsAllowInvalidCertificates` / `tlsAllowInvalidHostnames`
>   — the two flags every "fix my Atlas connection" answer online tells people to set.
> - **SQLite:** n/a (§4.3 is the file-permission analogue).
>
> And **enforce it in code, not in docs**: `PostgresAdapter`/`MongoAdapter` inspect the DSN at
> construction and **throw** under `NODE_ENV=production` if TLS is disabled or verification is
> downgraded (`sslmode=disable|allow|prefer`, `tlsAllowInvalidCertificates=true`). This is exactly
> the philosophy of the existing production guard in `resolve.ts`, which already refuses to silently
> fall back to a localhost Redis — a plaintext DSN in production is the same class of deploy mistake,
> with a worse blast radius. Localhost/socket connections are the documented exemption.

## 5. First-party adapters

New files under `src/storage/`, mirroring the existing `redis.ts` / `kv.ts` shape exactly — a thin
class over a structurally-typed `*Like` client interface, so the SDK never hard-depends on driver
types (the `RedisLike` / `KvLike` pattern):

| Adapter | File | Driver (optional peer) | Notes |
|---|---|---|---|
| `PostgresAdapter` | `src/storage/postgres.ts` | `pg` ^8 | Covers Postgres **and Supabase** (§4.1). Structurally accepts `@vercel/postgres` / `@neondatabase/serverless`. |
| `SqliteAdapter` | `src/storage/sqlite.ts` | `better-sqlite3` ^11 | Dev / self-host / single-instance only (§4.3) |
| `MongoAdapter` | `src/storage/mongo.ts` | `mongodb` ^6 | Read-path expiry filter **plus** TTL index (§3.2) |

Each ships the adapter class, its `*Like` structural interface, a one-shot `schema.sql`
(+ `supabase.sql`) or `ensureIndexes()`, and a lazy `import()`-based constructor so an unused
driver is never bundled or required — the pattern already in
[`resolve.ts:58-74`](../src/storage/resolve.ts#L58-L74).

## 6. `resolveStorageAdapter()` — additive detection, dispatched on URL scheme

The existing precedence (Upstash → Vercel KV → ioredis, plus the production
no-backend-configured guard, [`resolve.ts:28-52`](../src/storage/resolve.ts#L28-L52)) is preserved
exactly. New backends are checked **after** the existing three, so an app with both `REDIS_URL`
and `DATABASE_URL` set keeps resolving to Redis — **no deployment changes behavior on upgrade**:

```
0. TETRAC_STORAGE_DRIVER=<redis|upstash|vercelkv|postgres|mongo|sqlite>   → explicit override (new)
1. UPSTASH_REDIS_REST_URL + _TOKEN   → upstash              (existing, unchanged)
2. VERCEL or KV_REST_API_URL         → vercelkv             (existing, unchanged)
3. REDIS_URL                         → ioredis              (existing, unchanged)
4. DATABASE_URL / POSTGRES_URL / MONGODB_URI / SQLITE_PATH  → dispatch on scheme (new)
5. (non-prod only) localhost fallback → ioredis             (existing, unchanged)
```

**Dispatch on the URL scheme, not the variable name.** `DATABASE_URL` is a platform convention,
not a Postgres one — Railway, Render, and Fly all set it for MySQL and Mongo too. Mapping the
*name* to a driver would hand a `mysql://` URL to `pg`. Parse it: `postgres:`/`postgresql:` →
Postgres, `mysql:` → MySQL, `mongodb:`/`mongodb+srv:` → Mongo, `file:`/`sqlite:` → SQLite;
unrecognized scheme → **throw naming the scheme**, never guess.

If two *different* new-backend URLs are set at once, **throw** rather than pick — ambiguous config
is a deploy mistake, matching the philosophy of the existing partial-Upstash warning
([`resolve.ts:31-38`](../src/storage/resolve.ts#L31-L38)).

**Guardrails on the new `TETRAC_STORAGE_DRIVER` override** — it is the first env var that lets a
deployment *choose* a backend by name rather than by presenting its config, so it needs two limits
that the current implicit precedence gets for free:

- **`memory` is not an accepted value.** Ever, in any environment. `MemoryAdapter` is a per-process
  `Map`: as a production backend it silently gives each instance its own store — sessions that
  don't persist, challenges that don't replicate, and a **rate limiter that resets on every cold
  start**, which is to say no rate limiter at all. The whole point of the `resolve.ts` production
  guard is to refuse exactly this failure; a driver override that can name it would be a hole
  straight through that guard. Tests construct `MemoryAdapter` directly — they don't need the env
  var, and nothing else should have it.
- **Explicit driver + missing config ⇒ throw, never fall back.** `TETRAC_STORAGE_DRIVER=postgres`
  with no `DATABASE_URL` must be a hard error naming the missing variable. It must *not* fall
  through to the next rule in the precedence list, and above all not to the non-prod localhost
  Redis fallback — an operator who named a driver has stated an intent, and quietly honoring a
  different one is how you get a "working" staging deploy that was never touching the database it
  was configured for. Naming a driver is a stronger signal than presenting its config, and it
  should fail harder, not softer.

**The one required source edit:** the production guard currently throws when `NODE_ENV=production`
and `REDIS_URL` is unset ([`resolve.ts:43-49`](../src/storage/resolve.ts#L43-L49)). It must be
widened to accept the new backends too, or configuring Postgres in production would throw. It
**only ever widens** what is accepted — every env combination that resolves today resolves
identically after — and its existing test (`tests/storage.test.ts`, "production + NO backend env →
throws") must still pass unchanged, now joined by "production + `DATABASE_URL` → postgres, no throw".

The fully-manual path is unchanged and remains the documented answer for anything not
auto-detected (Couchbase, DynamoDB, custom): construct the adapter yourself and pass it to
`createNextAuthRoutes({ storage })`, bypassing `resolveStorageAdapter()` entirely.

## 7. Verification — the conformance suite

> ⚠️ **Superseded in part by [`PRD/ADR-001`](../PRD/ADR-001-storage-seam.md) (accepted).** The suite
> ships in `0.5.0` and targets **`AuthStore`** — the domain port — not `StorageAdapter`. KV backends
> are tested *through* `KvAuthStore`, so there is still exactly **one** acceptance bar. The cases
> below remain valid in substance; several are now expressed as *behavioral* assertions (e.g. "after
> the window elapses the identifier is allowed again") rather than as assertions about Redis
> primitives, which is what lets them transfer to a backend with no `INCR` at all. The authoritative
> case list is [`PRD/v0.5.0-PRD.md`](../PRD/v0.5.0-PRD.md) §3.4.

Today's adapter tests hand-roll near-identical assertions per adapter with per-adapter mocks
(`tests/storage.test.ts`, `storage-hash.test.ts`, `storage-kv.test.ts`). Extract them into one
reusable, **framework-agnostic** suite — it returns cases rather than calling `describe`/`it`, so
third-party authors can run it under Jest, Vitest, or `node:test`:

```ts
// src/storage/conformance.ts — exported at @tetrac/login-sdk/storage/conformance
export interface ConformanceCase { name: string; run(): Promise<void>; }   // throws on failure
export function authStoreConformanceCases(
  makeStore: () => AuthStore | Promise<AuthStore>,
  opts?: { advance?: (ms: number) => Promise<void> | void; supportsSweep?: boolean },
): ConformanceCase[];
```

Required cases — each maps to a §3 hazard, and each **must be written failing first** against a
deliberately-naive adapter, or it is not pulling its weight:

| Case | Guards |
|---|---|
| `incr` on an expired key returns `1` and clears the stale TTL | §3.1(b) — **permanent rate-limit lockout** |
| `incr` on a live key leaves its TTL untouched | §3.1(c) |
| `expire` on an absent/expired key creates nothing | §3.1(d) |
| expired key is invisible to `get`/`getdel`/`incr` **without** any reaper having run | §3.2 — **expired sessions/challenges** |
| concurrent `getdel` — exactly one caller observes the value | §4.4 — **challenge replay** |
| concurrent `hset` of two fields on one key — neither write is lost | §3.4 |
| **`hset`/`hget`/`hgetall` with a dotted field (`"myapp.example"`) round-trips as one flat field** | §3.4 — **Mongo nesting ⇒ cross-tenant data loss** |
| `set("K")` and `set("k")` are independent keys | §3.5 — **cross-account / cross-tenant collision** |
| **`set("k")` and `set("k ")` (trailing space) are independent keys** | §3.5 — **MySQL `PAD SPACE` collision** |
| a 64-wallet `UserData` blob round-trips byte-identical | §3.6 — **silent truncation ⇒ lockout** |
| **a key one byte over the column width throws — and does not truncate** | §3.6/§3.9 — **silent key collision** |
| injection-shaped keys/fields/values round-trip as inert data | §3.7 |
| `del` removes both the string and the hash keyspace | §3.8 |
| **a hash with many fields either returns them all or throws — never a silent partial** | §3.11 |
| `hgetall` returns `{}` (never `null`) for an absent key | existing contract |

Two contract items are **not** expressible as adapter-level cases and are enforced by review +
caller-side tests instead, which is worth stating so nobody assumes green CI covers them:
**§3.10** (errors fail closed) requires a *fault-injecting* adapter — a fake whose `incr` rejects —
asserting that `checkRateLimit` propagates rather than allowing; that belongs in the server tests,
not the storage conformance kit. **§3.9** (caller-side email validation) is a `routes.ts` test.

Run against: `MemoryAdapter`, `RedisAdapter`, `VercelKVAdapter`, `UpstashAdapter` (existing
mocks — regression baseline; the current tests fold in unchanged), `SqliteAdapter` (in-process,
temp file, no service dependency), and `PostgresAdapter` / `MongoAdapter` against **dockerized
real engines** in CI. Collation, `ON CONFLICT` atomicity, and TTL-sweep timing are properties of
the engine — a mock would assert only that we mocked it the way we imagined.

## 8. Non-breaking guarantee — merge checklist

- [ ] `StorageAdapter`'s 10 required methods: signatures unchanged. `sweepExpired?()` (§3.3) and
      `close?()` are **optional**; adapters omitting them stay structurally valid, and every
      caller feature-detects before invoking.
- [ ] `RedisAdapter`, `VercelKVAdapter`, `UpstashAdapter`: zero changes.
- [ ] `MemoryAdapter`: one intentional change — `del` also clears the hash keyspace (§3.8).
      Unobservable to callers; covered by a new conformance case.
- [ ] `routes.ts`: `/login` validates `body.email` before building a key (§3.9). Tightening only —
      it rejects inputs that are already outside the documented format and that `/register` has
      always rejected. **Prerequisite for the SQL adapters**, not a follow-up.
- [ ] `resolveStorageAdapter()`: for **every** env-var combination that resolves today, the
      resolved backend is identical. Only widened, never narrowed. Existing prod-guard test
      passes unchanged. `TETRAC_STORAGE_DRIVER` rejects `memory` and throws on a named-but-
      unconfigured driver (§6).
- [ ] **If §4.6 ships in this release** (separate decision — §10): `session.ts` + `crypto.ts`
      change, and the release notes must lead with **"all users are logged out once on upgrade"**.
      That is the only user-visible break in the whole PRD, and it must not arrive as a surprise.
      If §4.6 does **not** ship here, `docs/THREAT_MODEL.md` must state that raw session bearer
      tokens are stored in the database and that read access to the auth table is equivalent to
      full account takeover — because with SQL backends that is now a realistic, reachable claim
      (§4.1, §4.3, §4.8), not the theoretical one it was against a private Redis.
- [ ] `package.json` `dependencies`: unchanged. `pg` / `better-sqlite3` / `mongodb` go to
      `peerDependencies` + `peerDependenciesMeta.optional: true`, exactly as `ioredis` /
      `@upstash/redis` / `@vercel/kv` are today — an app that doesn't install them pays nothing
      at install time or in bundle size.
- [ ] `@tetrac/login-sdk/storage` export: additive only. Conformance ships on its own subpath so
      it never lands in a production server bundle.
- [ ] No change to stored data shape ⇒ **no migration** for existing deployments.

## 9. Rollout

0. **Phase 0 — the two prerequisites, mergeable on their own.** Neither depends on a new adapter,
   both are small, and both are load-bearing for everything after: the `/login` email validation
   (§3.9 — without it §3.6's column sizing is unsound) and the `MemoryAdapter.del` fix (§3.8).
   Land these first so Phase 1 is purely additive. §4.6 (session-token hashing) belongs here too if
   §10 resolves in favor.
1. **Phase 1 — the contract is the product.** §3 written into `adapter.ts`'s doc comments +
   a new `docs/STORAGE_ADAPTERS.md`; the conformance suite (§7); `PostgresAdapter` (covers
   Postgres **and** Supabase — the two most-requested backends) with `supabase.sql` (§4.1 exposure
   warning + §4.7 least-privilege role) and the §4.9 TLS assertion; `SqliteAdapter` (with §4.3's
   `0600` + not-under-`public/` checks).
2. **Phase 2 —** `MongoAdapter` (needs §3.2's read-path filter to be right, which is why it
   trails Postgres rather than shipping beside it).
3. **Phase 3 / community-eligible —** `MySQLAdapter` (needs §3.5 binary collation, §3.6
   `MEDIUMTEXT` + strict mode, and §4.4's transactional `getdel` — the three hardest hazards
   land together, so it is deliberately last), `CouchbaseAdapter`. Same contract, same
   conformance suite as the acceptance bar. Good external-contribution candidates **once Phase 1
   lands**, because by then the hard questions are answered generically and the test kit says
   yes or no.

## 10. Open questions

- **Does §4.6 (hash the session token) ship in `0.5.0`, or as its own release?** This is the one
  decision in the document with real consequences either way, so it should be made deliberately
  rather than defaulted. **Leaning: ship it in `0.5.0`.** The argument is timing, not novelty — the
  risk it removes is *created by this PRD*. Storing raw bearer tokens was defensible when the store
  was a private, ephemeral, in-memory Redis; the moment `0.5.0` invites people to point the SDK at
  a Supabase project, a nightly-backed-up Postgres, or a `.db` file, the same design becomes a
  standing liability with several independent leak paths (§4.1, §4.3, §4.7, §4.8). Shipping the
  backends *first* and the hashing *later* means every early SQL adopter runs the unhardened
  version through the exact window where the hazard is newest and least understood. Cost is one
  forced re-login (4h TTL, self-healing, no migration).
- Ship `close?()` now or on demand? Leaning **now**: zero-risk (optional), and Postgres/Mongo want
  it on day one for non-serverless (long-lived Node/Express) deployments.
- Reaper wiring (§3.3) — ship `sweepExpired()` plus *documentation* only (developer wires
  `pg_cron` / a cron route), or also ship an opportunistic in-process probabilistic sweep?
  **Revised leaning: the reaper is a deployment requirement, not an optional optimization, and
  "defer until someone reports table growth" is the wrong test.** The original framing treats dead
  rows as a *disk* problem, and on that framing deferral is obviously right. But look at what is
  actually in those rows. Rate-limit keys are built from the identifier — and the identifier is an
  **email address** (`register:{appId}:{email}`, `login:{appId}:{email}`,
  [`routes.ts:252`](../src/server/routes.ts#L252)) or a **client IP**. Against Redis those keys
  evict themselves after 60 seconds and the PII is genuinely gone. Against Postgres, with read-path
  expiry (§3.2) making them merely *invisible*, they sit in the table — and in every backup and
  replica — **indefinitely**. Expired-but-unswept session rows keep their tokens there too (until
  §4.6). "Nobody complained about disk" is not evidence that the data-retention posture is fine;
  it is evidence that nobody is looking. So: ship `sweepExpired()` + docs + a **loud startup
  warning when a SQL/Mongo adapter is constructed with no sweep wired**, and treat the opportunistic
  in-process sweep as the zero-config default worth paying tail latency for. A store that silently
  retains user emails and IPs forever is a compliance finding, not a housekeeping backlog item.
- [`docs/THREAT_MODEL.md:85`](THREAT_MODEL.md) currently says production storage means *"a
  persistent KV/Redis"* — reword to "a persistent, durable, conformant adapter" and add per-backend
  transport-security guidance (**`sslmode=verify-full`**, not `require` — §4.9 — and `tls=true`),
  plus §4.1's exposure note. The threat model also needs a row for **storage-layer
  misconfiguration** as a first-class trust-boundary failure — §4.1 is precisely that, and the
  current model has no line for it. The deeper edit is that the threat model's implicit assumption
  — *the datastore is a trusted, private, single-tenant component* — is what `0.5.0` retires. A
  Supabase project with a PostgREST front door, a nightly-backed-up RDS instance, a SQLite file on
  a shared host, and a Mongo cluster with the profiler on are all in scope now, and each of them
  makes "an attacker who can read the storage layer" a **realistic** actor rather than a
  game-over-anyway one. §4.6 is what keeps that actor from being game-over.
- Should the production guard **refuse SQLite** under `NODE_ENV=production`? It is a legitimate
  self-host choice, but it is also exactly the kind of thing that gets deployed to a
  multi-instance platform by accident, where it silently gives each instance a private store —
  the same failure the existing localhost-Redis guard was written to prevent
  ([`resolve.ts:43-49`](../src/storage/resolve.ts#L43-L49)). Leaning: allow, but require an
  explicit `TETRAC_ALLOW_SQLITE_IN_PRODUCTION=1` opt-in, so it can only happen on purpose.
