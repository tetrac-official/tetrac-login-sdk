// The SQL backend ports (ADR-002).
//
// THE WHOLE POINT: these interfaces know NOTHING about authentication.
//
// Before ADR-002, backing the SDK with Postgres meant implementing `AuthStore` from
// scratch — nine methods — and independently getting right: expiry-on-read, atomic
// challenge consume, rate-limit window semantics, no-lost-write on the email index,
// email normalization, binary collation, column sizing, and injection safety. Eight
// correctness rules, per database. That is a security exam, not an extension point, and
// it is why every new engine turned into a fresh security review.
//
// Now the SDK owns all of that (see ./engine.ts). A backend supplies only:
//
//   * a SqlDriver  — "run this parameterized statement" + "run this in a transaction"
//   * a SqlDialect — the handful of things that genuinely differ between SQL engines
//
// A driver author cannot introduce a rate-limit lockout, because a driver author never
// writes a rate limiter. That is the entire design.

/**
 * Execute parameterized SQL. That is the entire contract.
 *
 * NEVER interpolate values into `sql` — every value arrives in `params`. The engine
 * builds all statements from templates and binds every value, so a driver that honors
 * this is injection-safe by construction.
 */
export interface SqlDriver {
  /** Run a statement and return its rows (empty array for writes with no RETURNING). */
  query<T = Record<string, unknown>>(sql: string, params: readonly unknown[]): Promise<T[]>;
  /**
   * Run `fn` inside a transaction, passing a driver bound to that transaction. Roll back
   * if it throws. The engine uses this where an engine lacks `RETURNING` (MySQL), so the
   * atomicity of challenge-consume and rate-limiting depends on this being a REAL
   * transaction — not a no-op passthrough.
   */
  transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T>;
  /** Release pooled connections. Optional — omit for drivers with nothing to release. */
  close?(): Promise<void>;
}

/** A problem found by {@link SqlDialect.preflight}. */
export interface PreflightIssue {
  /** `error` refuses to boot. `warn` logs loudly and continues. */
  level: "error" | "warn";
  /** Stable machine-readable code, e.g. `supabase_public_schema`. */
  code: string;
  message: string;
}

/**
 * The ONLY things that genuinely differ between SQL engines.
 *
 * Note what is absent: no `getUser`, no `hitRateLimit`, no expiry, no TTL, no notion that
 * this is an auth system. Adding a new SQL engine is implementing this — roughly 30 lines
 * — and the engine inherits every correctness guarantee for free.
 */
export interface SqlDialect {
  readonly name: string;

  /** Fully-qualified table names. Postgres puts them in a dedicated schema (never `public`). */
  readonly tables: SqlTables;

  /** Positional placeholder for the i-th (0-based) parameter: `$1` on Postgres, `?` elsewhere. */
  placeholder(i: number): string;

  /**
   * Does this engine support `RETURNING` on INSERT/DELETE?
   *
   * **MySQL: false** — and that is not cosmetic. `takeChallenge` MUST be an atomic
   * get-and-delete (it is the sole defense against challenge replay), and `hitRateLimit`
   * must increment-and-read atomically. Where this is false the engine wraps both in a
   * transaction with `SELECT … FOR UPDATE`. The dialect declares the limitation; the
   * engine handles it. This is the difference between "MySQL is hard" and "MySQL is
   * thirty lines".
   */
  readonly supportsReturning: boolean;

  /** Row-lock suffix for a `SELECT` inside a transaction (`FOR UPDATE`). Empty if unsupported. */
  readonly forUpdate: string;

  /**
   * The upsert clause. Postgres/SQLite: `ON CONFLICT (a,b) DO UPDATE SET …`.
   * MySQL: `ON DUPLICATE KEY UPDATE …` (which ignores `conflictCols`).
   *
   * `setClauses` carry their own bound placeholders — the engine binds the value twice
   * rather than using `excluded.col` / `VALUES(col)`, which differ per engine and are
   * deprecated on MySQL 8.0.20+. One less thing for a dialect to get wrong.
   */
  upsert(conflictCols: readonly string[], setClauses: readonly string[]): string;

  /** `DELETE FROM <table> WHERE expires_at <= ?` bounded to `limit` rows. Postgres has no
   *  `DELETE … LIMIT`, so it needs a subquery — hence a dialect method. */
  deleteExpiredLimited(table: string, limit: number, placeholderIndex: number): string;

  /** The complete schema. The SDK emits this — the integrator never picks a type or a collation. */
  ddl(): string;

  /** Checks run at construction. See ./preflight.ts for why this is code and not prose. */
  preflight(driver: SqlDriver): Promise<PreflightIssue[]>;
}

/** Fully-qualified table names, so a dialect can put them in a non-`public` schema. */
export interface SqlTables {
  users: string;
  emailIndex: string;
  sessions: string;
  challenges: string;
  rateLimits: string;
}
