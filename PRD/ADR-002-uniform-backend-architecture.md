# ADR-002 — Absorb the variance: one engine, thin drivers

**Problem:** adding a second database turned into a per-database security review. Every backend
re-litigates expiry, atomicity, collation, key sizing, and injection — and the answers differ by
engine. The migration guide is therefore different for every database, and each one is a fresh
opportunity to ship a silent, catastrophic bug.

- **Status:** ✅ **ACCEPTED AND IMPLEMENTED** (SQL tier). Supersedes the *implementation strategy* of
  `docs/MULTI_DB.md` (its per-engine hazard analysis stays valid — it becomes the SDK's internal spec
  instead of the integrator's homework). Does **not** revisit
  [`ADR-001`](./ADR-001-storage-seam.md); `AuthStore` stays.

### What landed

| Piece | Status | Where |
|---|---|---|
| `SqlDriver` / `SqlDialect` — the dumb driver port | ✅ | `src/storage/sql/types.ts` |
| **`SqlAuthStore`** — the engine. Every correctness rule, written once | ✅ | `src/storage/sql/engine.ts` |
| Postgres dialect (⇒ Supabase, Neon, RDS, Railway, Render, Fly, CockroachDB) | ✅ | `dialects/postgres.ts` |
| SQLite dialect (⇒ libSQL/Turso) | ✅ | `dialects/sqlite.ts` |
| **MySQL dialect** — the acid test | ✅ | `dialects/mysql.ts` |
| Thin drivers (`pg` / `mysql2` / `better-sqlite3`), structurally typed | ✅ | `drivers.ts` |
| Preflight that **refuses to boot** | ✅ | per-dialect `preflight()` |
| Generated DDL (`schemaFor`) | ✅ | per-dialect `ddl()` |
| Full conformance suite on a **real SQL engine** | ✅ | `tests/sql-conformance-sqlite.test.ts` (24/24) |
| Same suite on **real Postgres** — proves the dialect abstraction | ✅ | `tests/sql-conformance-postgres.test.ts` (CI) |
| `DocumentAuthStore` (Mongo / DynamoDB / Firestore) | ⬜ Next | — |
| Convex component | ⬜ On demand | — |

**The claim, tested:** the same engine code passes all 24 conformance cases on SQLite *and* on
Postgres, with nothing changing but a ~30-line dialect. MySQL's three notorious hazards (no
`DELETE…RETURNING`, case-insensitive collation, silent truncation) are handled by
`supportsReturning: false`, `VARBINARY` in the generated DDL, and a preflight that refuses to boot
if strict mode is off. **None of them are ever the integrator's problem.**
- **Decision:** **the SDK owns the correctness logic; a backend supplies only a driver.** Ship one
  `SqlAuthStore` (+ a ~30-line dialect per engine) and one `DocumentAuthStore`, rather than asking
  anyone to implement `AuthStore` from scratch.
- **Effect:** the eight correctness rules a backend author must currently satisfy drops to **zero**.
  The migration guide becomes **the same four steps for every database**.

---

## 1. The mistake in ADR-001

ADR-001 was right that `StorageAdapter` was the wrong *shape* — `incr(key)` is a primitive that
forbids the only correct implementation on an OCC engine. `AuthStore` fixed that.

But `AuthStore` is a **thin port**, and that is a second mistake, hiding behind the first. It says
*"implement these nine methods correctly"* and leaves *correctly* entirely to you. Today the SDK ships
exactly one reusable helper (`normalizeEmail`) and one implementation (`KvAuthStore`). So a Postgres
author writes all nine methods from scratch and must independently get right:

1. expiry enforced on the **read path** (not delegated to a TTL/sweeper)
2. atomic get-and-delete for challenges (or replay)
3. rate-limit **window** semantics (or a permanent lockout)
4. no-lost-write on the email index
5. `normalizeEmail` — and *not* a case-insensitive collation
6. binary, non-padding collation
7. key/value column sizing
8. parameterization / NoSQL structural injection

**That is not an extension point. That is a security exam.** And it is the direct cause of the
symptom: eight hazards × N databases = an unmaintainable matrix, a different migration guide per
engine, and a real chance that a community adapter quietly locks users out.

The tell: `docs/MULTI_DB.md` is eleven pages of *"here is how to correctly emulate the thing we
already know how to do."* **If we know the right answer well enough to write it down that precisely,
we should write it in code, once.**

## 2. The fix: push the variance down, not out

Split the port in two, and put the correctness in the middle where we control it.

```
        ┌──────────────────────────────────────────────────────────┐
        │  server layer (routes / session / challenge / rateLimit) │
        └──────────────────────────┬───────────────────────────────┘
                                   │  AuthStore  (ADR-001 — unchanged)
        ┌──────────────────────────┴───────────────────────────────┐
        │        THE ENGINE — SDK-owned, written ONCE, tested ONCE  │
        │                                                           │
        │  SqlAuthStore        DocumentAuthStore      KvAuthStore   │
        │  ─────────────       ─────────────────      ───────────   │
        │  • expiry-on-read    • expiry-on-read       (exists)      │
        │  • window logic      • window logic                       │
        │  • atomic consume    • atomic consume                     │
        │  • normalizeEmail    • normalizeEmail                     │
        │  • parameterized     • scalar-only filters                │
        │  • owns the DDL      • owns the indexes                   │
        └──────────────────────────┬───────────────────────────────┘
                                   │  a DUMB driver port
        ┌──────────────────────────┴───────────────────────────────┐
        │  SqlDriver + SqlDialect          DocumentDriver           │
        │  pg · mysql2 · better-sqlite3    mongodb · dynamodb       │
        │  (~30 lines each. No auth semantics. Nothing to get wrong)│
        └───────────────────────────────────────────────────────────┘
```

### The driver port is deliberately stupid

```ts
/** Execute parameterized SQL. That is the entire contract. */
export interface SqlDriver {
  query<T>(sql: string, params: unknown[]): Promise<T[]>;
  transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T>;
  close?(): Promise<void>;
}

/** The ONLY things that genuinely differ between SQL engines. */
export interface SqlDialect {
  placeholder(i: number): string;          // "$1"  |  "?"
  upsert(table: string, keys: string[], set: string[]): string;   // ON CONFLICT | ON DUPLICATE KEY
  supportsDeleteReturning: boolean;        // false on MySQL → the engine uses a transaction instead
  ddl(): string;                           // the schema — with the RIGHT types and collation
  preflight(): PreflightCheck[];           // §4
}
```

Note what is **not** in there: no `getUser`, no `hitRateLimit`, no expiry, no TTL, no notion that this
is an auth system at all. A driver author cannot introduce a rate-limit lockout, because a driver
author never writes a rate limiter.

### Every hazard becomes an SDK implementation detail

| Hazard (today: the integrator's problem) | Under this ADR |
|---|---|
| Expiry on read | **`SqlAuthStore`** puts `expires_at > now()` in the query template. Not optional, not forgettable. |
| Rate-limit window (permanent lockout) | **One upsert template**, with the `CASE` that starts a fresh window on an expired row. Written once. |
| Atomic get-and-delete (challenge replay) | `DELETE…RETURNING` where the dialect supports it; a transaction where it doesn't. **The engine picks.** |
| Lost write on the email index | The **SDK's DDL**: `PRIMARY KEY (email, app_id)`. Structurally impossible to lose. |
| `normalizeEmail` vs collation | The engine calls `normalizeEmail()` before it ever touches the driver. |
| Binary / non-padding collation | The **SDK emits the DDL** — `VARBINARY` on MySQL. The integrator never picks a collation. |
| Key & value sizing | Same. The SDK emits `MEDIUMTEXT`, not the user. |
| Injection (SQL + structural NoSQL) | The engine builds every statement from templates with bound parameters. Values never reach a query string. |

**Eight → zero.** Not documented-away: *unrepresentable*.

## 3. What this actually buys

- **One migration guide, four steps, every database** (§5). That is the ask.
- **Adding MySQL becomes ~30 lines of dialect**, not a security review. The hard MySQL problems (no
  `DELETE…RETURNING`, case-insensitive collation, silent truncation) are solved *in the engine and the
  DDL* — the dialect just declares `supportsDeleteReturning: false` and emits `VARBINARY`/`MEDIUMTEXT`.
- **The conformance suite changes role.** Today it is the acceptance bar an integrator must clear.
  It becomes a **regression suite for our own engine**, run against every dialect in CI on real
  engines. Integrators still *can* run it (it stays exported), but they no longer *have to* — because
  they are no longer the ones who can break it.
- **`docs/MULTI_DB.md` stops being homework.** Its per-engine hazard analysis was always correct; it
  just had the wrong audience. It becomes the **internal spec for the dialects** — the thing a
  maintainer reads before touching `MysqlDialect`.

## 4. Deployment posture: check it, don't document it

Two classes of problem survive, because they are not code:

- **Supabase's `public` schema is world-readable** via PostgREST + the browser-shipped `anon` key.
- **TLS that doesn't verify** (`sslmode=require` accepts *any* certificate), over-privileged roles,
  parameter-logging.

Prose does not stop these. **A preflight does:**

```ts
const store = await createSqlAuthStore({ client });   // runs preflight() on construction
```

- **Refuses to boot** (throws) on: tables resolving to `public` on a `*.supabase.co` host; a plaintext
  or unverified DSN under `NODE_ENV=production`; MySQL not in strict mode.
- **Warns loudly** on: no sweeper wired; a non-deterministic Postgres collation; a SQLite file that is
  world-readable or sits under a web-served directory.

A misconfiguration that would silently expose every session token and wallet blob should be a **failed
deploy**, not a paragraph someone skimmed.

## 5. The migration guide this produces — identical for every database

```bash
# 1. install the driver you already use
npm i pg            # or mysql2 / better-sqlite3 / mongodb / @aws-sdk/client-dynamodb
```

```bash
# 2. create the schema (the SDK emits it — do not hand-roll it; the DDL is load-bearing)
npx tetrac-db schema --postgres > schema.sql   # --mysql --sqlite --supabase
psql < schema.sql
```

```ts
// 3. point the SDK at it — the ONLY line that differs between databases
import { createSqlAuthStore } from "@tetrac/login-sdk/storage/sql";
const store = await createSqlAuthStore({ client: pool });   // preflight runs here

export const { GET, POST } = createNextAuthRoutes({ store });
```

```ts
// 4. wire the sweeper (space + PII retention — dead rate-limit rows hold emails and IPs)
export const GET = () => store.sweepExpired();   // hit it from a cron
```

Four steps. The database name appears **twice** — in the install and in the schema flag. Nothing about
challenges, sessions, expiry, collation, or rate limits appears anywhere, because none of it is the
integrator's problem any more.

## 6. Cost, honestly

- **It is more SDK code than the current plan**, and it is code we own forever. That is the trade:
  we absorb the complexity instead of exporting it to N integrators who will each get it subtly wrong.
- **The `AuthStore` port stays public.** Anyone who genuinely needs a bespoke backend (Convex, a
  homegrown store) can still implement it directly, with the conformance suite as their bar. We are
  removing the *obligation*, not the *option*.
- **A dialect can still be wrong** — but the blast radius is one dialect, in our repo, covered by the
  conformance suite against a real engine in CI, rather than in a stranger's production deployment.
- **Convex still doesn't fit the driver model** (no external DB access; it ships as a component). That
  remains true and remains out of scope. It is the exception that the architecture correctly refuses
  to pretend about.

## 7. Recommendation

Adopt. Retarget `0.6.0` from *"ship a `PostgresAdapter`"* to *"ship the engine + the Postgres and
SQLite dialects."* Same delivery, an order of magnitude less risk per additional database afterwards —
and the migration guide the SDK actually promised.

**Sequencing:** the engine + `SqlAuthStore` + Postgres/SQLite dialects (`0.6.0`) → MySQL dialect
(`0.6.x`, cheap once the engine exists) → `DocumentAuthStore` + Mongo (`0.7.0`) → DynamoDB → Convex
component (on demand).
