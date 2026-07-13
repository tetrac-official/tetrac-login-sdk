# ADR-001 — The storage seam: `StorageAdapter` (KV) vs `AuthStore` (domain)

**Question:** our goal is "back the SDK with any third-party database." Convex cannot be backed by
the current `StorageAdapter` without degenerating under load. Is `StorageAdapter` the wrong seam —
and if so, do we re-engineer it now?

- **Status:** 🟡 Proposed — decision required before `PRD/v0.5.0-PRD.md` §3 (the conformance suite)
  is built, because the suite is the acceptance bar for whichever interface we pick. Building it
  against the wrong seam is the one genuinely wasteful outcome available to us.
- **Recommendation:** **Yes — introduce a domain-level `AuthStore` port, additively.** Keep
  `StorageAdapter` as a *KV-backend* contract, and ship `KvAuthStore`, which implements `AuthStore`
  on top of any `StorageAdapter`. Redis / Upstash / Vercel KV / Memory keep working **unchanged**.
  Convex, Postgres, DynamoDB, Firestore, and Durable Objects implement `AuthStore` **natively**.
- **TL;DR of the argument:** roughly **half the hazards** catalogued in `docs/MULTI_DB.md` are not
  intrinsic to the problem — they are **artifacts of the KV seam**, and they disappear when the port
  is expressed in the domain's own vocabulary. Convex is what made this visible, but it is not a
  Convex-specific finding.

---

## 1. What Convex actually forced us to notice

Convex is not a database you connect a driver to. Two documented facts break the current design:

**(a) External code cannot touch the database at all.** Every read and write must go through
**functions deployed into the customer's own `convex/` directory**; an external Node/Next.js server
calls them via `ConvexHttpClient`. There is no `ctx.db` outside the Convex function runtime. So a
`ConvexAdapter` living in our npm package **cannot implement `incr` or `getdel` atomically by
itself** — it can only *invoke* something the developer has already deployed. The adapter's logic
has to ship *into the customer's backend*.

**(b) Convex uses optimistic concurrency control, and its own error documentation uses *our exact
data structure* as the worked example of what not to do.** Verbatim, from
[docs.convex.dev/error](https://docs.convex.dev/error) § "Write conflict: Optimistic concurrency
control":

> *"A mutation `updateCounter` always updates the same document… If this mutation is called many
> times per second, many of its executions will conflict with each other. **Convex internally does
> several retries to mitigate this concern, but if the mutation is called more rapidly than Convex
> can execute it, some of the invocations will eventually throw this error:** … Documents read from
> or written to the table "counters" changed while this mutation was being run **and on every
> subsequent retry**."*

Their example code is `ctx.db.patch(doc._id, { value: doc.value + 1 })`. **That is `INCR` on a hot
key.** Their remediation #3 is: *"Design your data model such that it doesn't require making many
writes to the same document."*

**A rate-limit counter is, by definition, many writes to the same document.** That is the whole
data structure. So the obvious `incr(key)` on Convex conflicts, retries, and then **throws** under
precisely the burst traffic a rate limiter exists to survive. The failure is not merely unfortunate,
it is *inverted*: the control breaks hardest exactly when it is needed. And the retry count is **not
documented** — "several retries" is the only wording in the entire corpus — so there is no number we
could even design against.

Convex's own answer is to **shard the counter**. Their official `@convex-dev/rate-limiter` component
does exactly this — power-of-two-choices across shards, with the window lazily recomputed from
`(value, ts)` at read time so *"storage is not proportional to requests"*, and it explicitly *"fails
closed, not open."* It is, in other words, a correct rate limiter, already written.

**We cannot use any of it.** `StorageAdapter.incr(key)` is a *primitive*, not a *decision*: it hands
the backend a mechanism and denies it the intent. Sharding is invisible to a backend asked
`hitRateLimit(...)` and *impossible* for one asked `INCR`. **The port forbids the only correct
implementation.**

**(c) Convex has no TTL at all.** A grep of the full 2.3 MB docs corpus returns **zero** matches for
document TTL. Expiry must be hand-rolled — `ctx.scheduler.runAfter` (which is *atomic with the
enclosing mutation*, a genuinely nice property) or a cron sweep — which means **expiry-on-read is
mandatory**, exactly as our contract already demands. Fine. But `StorageAdapter.expire(key, seconds)`
models a *primitive Redis TTL* the backend does not have, forcing every non-Redis adapter to emulate
a command instead of expressing an intent.

**(d) And it is metered and concurrency-capped.** Convex bills per function invocation (1M/month
free) and caps queries/mutations at **1 second** — and, on the Free/Starter tier, at **16 concurrent
mutations** (S16). Our email-login path currently performs **~7 sequential storage round trips**
(`hget` → `get` → `getdel` → `del` → `set` → `set` → `hset`). On Redis at sub-millisecond that is
free. On Convex it is 7 billable calls, ~350 ms of added latency per login, and 7× the pressure on a
16-slot concurrency budget. **The chattiness of the KV port is not just slow here — it is a line
item and a scaling ceiling.**

---

## 2. The deeper finding: the hazards are artifacts of the seam

This is the part that matters beyond Convex. Re-read `docs/MULTI_DB.md` §3 and ask, for each hazard,
*"would this exist if the port spoke the domain's language?"*

| Hazard (MULTI_DB §) | Exists because… | Survives a domain port? |
|---|---|---|
| **§3.1 `incr` on an expired key ⇒ permanent rate-limit lockout** 🚨 | rate limiting is split into `incr` + `expire`, with the caller *inferring* a new window from `count === 1` | **NO — becomes unrepresentable.** `hitRateLimit(key, window, max)` is one atomic call that returns a decision. There is no two-step dance to get wrong. |
| **§3.5 binary/non-padding collation** | we concatenate `appId` + base58 pubkeys + emails into **one opaque string key**, then demand the engine compare it byte-exactly | **NO** for native backends — `appId` and `publicKey` become typed columns/fields with their own indexes. Nothing to collate wrongly. |
| **§3.6 key sizing / silent truncation** | same — a 404-byte synthetic key must fit a column | **NO** for native backends. No synthetic key exists. |
| **§3.9 unbounded key substrings** | same — an unvalidated email becomes part of a key | **Mostly no.** (Still validate the email; but it is a field, not a key fragment.) |
| **§3.8 `del` across two keyspaces** | we exposed a raw, typed keyspace and then had to define `DEL`'s cross-type semantics | **NO.** No raw keyspace is exposed. |
| **§3.4 per-field hash atomicity** | the email index is a *hash* because the KV port had no better way to express "one row per (email, appId)" | **Reframed:** becomes "`linkEmail` must not lose a concurrent write" — a unique index or a transaction. Still a requirement, but a *natural* one. |
| §3.2 expiry enforced on read | the backend's TTL may be a sweep | **YES — survives.** `getSession`/`takeChallenge` must still never return an expired value. |
| §3.3 reaper for space (+ PII retention) | dead rows accumulate | **YES — survives.** |
| §3.7 injection safety | values are attacker-influenced | **YES — survives.** |
| §3.10 fail closed | errors must not become benign defaults | **YES — survives.** |
| §4.x TLS, least-privilege, Supabase exposure, logs | deployment concerns | **YES — survive.** Orthogonal to the seam. |

**Six of the eleven correctness hazards are self-inflicted by the KV seam.** They exist because we
serialize domain identities into opaque strings and emulate Redis primitives on engines that have
better tools. The remaining five are real and survive either way — and they are exactly the ones a
conformance suite should be enforcing.

That is the argument. Not "Convex needs a special case," but "**the port is Redis-shaped, and every
non-Redis backend pays for it.**"

## 3. The seam we already have, hiding in plain sight

The domain layer is **already written**. Every storage access in the server goes through exactly
nine functions in `session.ts`, `challenge.ts`, and `rateLimit.ts` — `routes.ts` never touches
`storage` directly except to pass it down. The port is sitting there; it simply isn't an interface.

```ts
// src/storage/store.ts — the proposed port. Not a new design: a promotion of what exists.
export interface AuthStore {
  // users
  getUser(appId: string, publicKey: string): Promise<UserData | null>;
  putUser(user: UserData): Promise<void>;                  // upsert + maintain the email index
  getPublicKeyByEmail(appId: string, email: string): Promise<string | null>;

  // challenges — single-use, TTL-bound
  putChallenge(appId: string, publicKey: string, challenge: string, ttlSeconds: number): Promise<void>;
  /** ATOMIC. Returns the stored challenge and removes it. null if absent OR expired.
   *  The caller does the constant-time compare — never the backend. */
  takeChallenge(appId: string, publicKey: string): Promise<string | null>;

  // sessions — keyed by the token's SHA-256 digest (never the token: v0.5.0 §1)
  putSession(appId: string, tokenHash: string, s: SessionValue, ttlSeconds: number): Promise<void>;
  getSession(appId: string, tokenHash: string): Promise<SessionValue | null>;   // null if expired
  deleteSession(appId: string, tokenHash: string): Promise<void>;

  // rate limiting — ONE atomic call that returns a DECISION, not a counter.
  // The bucket is STRUCTURED, not a concatenated string: that is the last opaque key in the
  // system, and passing it as fields is what lets a backend index it (and shard it — §5).
  hitRateLimit(
    bucket: { endpoint: string; appId: string; identifier: string },
    windowSeconds: number,
    maxAttempts: number,
  ): Promise<RateLimitResult>;

  // lifecycle — optional, feature-detected
  sweepExpired?(limit?: number): Promise<number>;
  close?(): Promise<void>;
}
```

Eleven methods against the KV port's ten — **no larger, and each one is easier to implement
correctly**, because you write the query your database is actually good at instead of emulating a
Redis command. Two incidental wins fall out for free:

- `SessionValue` is `{ publicKey, fingerprint? }`, which **deletes the `publicKey|fingerprint`
  string-splitting hack** in `session.ts` (whose correctness currently rests on "wallet public keys
  never contain `|`").
- `putUser` can write the record **and** the email index in **one transaction** on any real backend.
  Today it is two non-atomic calls (`set` + `hset`).

## 4. What this costs, honestly

- **`StorageAdapter` does not die, and Redis users feel nothing.** `KvAuthStore` implements
  `AuthStore` over any `StorageAdapter`. It is essentially today's `session.ts`/`challenge.ts`/
  `rateLimit.ts` bodies, moved behind the interface. `RedisAdapter`, `UpstashAdapter`,
  `VercelKVAdapter`, and `MemoryAdapter` change **not at all**.
- **`createNextAuthRoutes({ storage })` keeps working.** It accepts a `StorageAdapter` and wraps it
  in `KvAuthStore` automatically; a new `{ store }` option takes a native `AuthStore`. Additive.
- **The `hitRateLimit` contract must be written carefully**, because it is now the backend's job to
  get the window right. The §3.1 lockout bug does not vanish by magic — it becomes *the backend's
  single atomic statement to write correctly*, which is exactly where it belongs, and the conformance
  suite tests the observable behavior ("after the window elapses, the identifier is not still
  locked") rather than a primitive's semantics.
- **Two conformance suites, or one?** One. The `AuthStore` suite is the acceptance bar; KV backends
  are tested *through* `KvAuthStore`. The existing KV-primitive tests stay as unit tests of
  `KvAuthStore` itself.
- **It is a real refactor of `src/server/`.** `session.ts`, `challenge.ts`, and `rateLimit.ts` stop
  taking `storage: StorageAdapter` and start taking `store: AuthStore`. Mechanical, but it touches
  every route.

## 5. What a Convex backend then looks like (not being built now — see §6)

Convex has a first-class mechanism for exactly our situation, and it validates the seam decision.
**Convex Components** are *"like mini self-contained Convex backends"* with **their own private
tables** — *"They can't read your app's tables or call your app's functions unless you pass them in
explicitly."* One npm package can ship **both** normal client/server code **and** a component
(documented exports: `.`, `./convex.config.js`, `./_generated/component.js`). The customer writes
two lines:

```ts
// the customer's convex/convex.config.ts
const app = defineApp();
app.use(tetrac);          // our component: its own tables, its own functions, its own cron
export default app;
```

Three things then fall out that are **strictly better than what Redis or Postgres can give us**:

- **`hitRateLimit` becomes one sharded mutation.** It can delegate to — or copy — Convex's own
  `@convex-dev/rate-limiter`: power-of-two-choices sharding, lazy `(value, ts)` window recompute, no
  per-request row, no sweep. The §1(b) contention problem is solved **inside the backend, invisibly**,
  which is possible *only* because the port asked for a decision instead of an `INCR`.
- **The component ships its own cron.** `@convex-dev/action-cache` registers `crons.interval(...)`
  *inside the component* and purges expired rows in batches, self-rescheduling. So the customer
  never wires a sweeper — `sweepExpired` is satisfied by the component itself.
- **Writes commit transactionally with the app's own mutation:** *"All writes for a top-level
  mutation call, including writes performed by calls into other components' mutations, are committed
  at the same time,"* with each component call an isolated **sub-transaction** that can roll back
  alone. Challenge-consume + session-create + rate-limit-hit can be **one atomic unit with the
  customer's own writes** — something neither Redis nor Postgres offers today.

And auth-in-a-component is a well-trodden path, not an experiment: `@convex-dev/better-auth`,
`@convex-dev/workos-authkit`, `convex-passkey-auth`, and others already ship this way. Convex Auth's
own session table uses an `expirationTime` column checked **at read time** — i.e. it independently
arrived at our §3.2 expiry-on-read contract.

**Two Convex-specific traps to record now, so a future implementer doesn't rediscover them:**

- **OCC conflicts appear to be document-granular, not field-granular.** Convex's conflict error is
  phrased per-*document* ("Documents read from or written to the table … changed"). So two concurrent
  writes to *different fields of the same document* are expected to conflict — whereas Redis `HSET`
  on disjoint fields of one hash does **not**. The email index must therefore be **one document per
  (email, appId)**, never one document with a field per tenant. *(Strongly implied by the docs, not
  stated outright — worth an empirical test before building.)*
- **A long key cannot be a Convex field *name*** (64-char cap), only a field *value*. Which is fine —
  and is another instance of the same lesson: stop encoding domain identity into names and keys.

> **Also note there is no unique-constraint** in Convex (`.unique()` is a query helper that *throws*
> on >1 match, not an index constraint). Uniqueness is a read-then-insert inside a mutation — safe
> under serializability, but it puts the row in the read set and so feeds contention.

## 6. Decision — ✅ ACCEPTED

**1. Adopt `AuthStore`, additively, in `0.5.0`.**

Not because it is urgent, but because `0.5.0`'s central deliverable is the **conformance suite**, and
a suite is a *commitment to an interface*. Build it against `StorageAdapter` and we either throw it
away or freeze the Redis-shaped port permanently. The seam is cheapest to change in the release that
has **no third-party adapters in the wild** — and `0.5.0` is the last such release. `0.5.0` remains
Redis-only; the seam change is invisible to every existing deployment.

**2. Seam only — do NOT build a Convex backend yet.**

The point of this ADR is to make Convex-class backends *expressible*, not to chase them. Postgres
remains the first native `AuthStore` backend in `0.6.0` — it is still most of the addressable market
(see `v0.5.0-PRD.md` §9). Convex is the **proof that the seam is right**, and its component design
(§5) is recorded here so that building it later is a known quantity rather than a research project.

Concretely, this means `PRD/v0.5.0-PRD.md` §3 changes from *"a `StorageAdapter` conformance suite"*
to *"the `AuthStore` seam + a conformance suite against it,"* and `session.ts` / `challenge.ts` /
`rateLimit.ts` are refactored to take an `AuthStore` instead of a `StorageAdapter`.

> **The generalizable lesson, worth writing on the wall:** we shipped a port named for what it *is*
> (a key-value store) rather than for what it is *for* (authentication state). That inverted the
> dependency — every backend now has to emulate Redis instead of doing what it is good at, and we
> compensated by writing eleven pages of hazards telling implementers how to emulate Redis
> *correctly*. Convex did not break the design; it just refused to pretend.
