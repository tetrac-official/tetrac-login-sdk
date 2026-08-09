// The public SQL surface (ADR-002).
//
//   import { createPostgresAuthStore } from "@tetrac/login-sdk/storage/sql";
//   const store = await createPostgresAuthStore({ client: pool });   // preflight runs here
//   export const { GET, POST } = createNextAuthRoutes({ store });
//
// That is the whole integration, and it is the SAME shape for every engine. Nothing about
// challenges, sessions, expiry, collation, or rate limits appears anywhere, because none of
// it is the integrator's problem any more — see PRD/ADR-002.
import type { AuthStore } from "../store.js";
import { SqlAuthStore, type SqlAuthStoreOptions } from "./engine.js";
import type { PreflightIssue, SqlDialect, SqlDriver } from "./types.js";
import { postgresDialect, type PostgresDialectOptions } from "./dialects/postgres.js";
import { sqliteDialect, type SqliteDialectOptions } from "./dialects/sqlite.js";
import { mysqlDialect } from "./dialects/mysql.js";
import {
  pgDriver,
  mysqlDriver,
  sqliteDriver,
  type PgLike,
  type MysqlLike,
  type SqliteLike,
} from "./drivers.js";

export { SqlAuthStore } from "./engine.js";
export { postgresDialect, sqliteDialect, mysqlDialect };
export { pgDriver, mysqlDriver, sqliteDriver };
export type { SqlDriver, SqlDialect, PreflightIssue, SqlTables } from "./types.js";
export type { PgLike, MysqlLike, SqliteLike } from "./drivers.js";
export type { SqlAuthStoreOptions } from "./engine.js";

/** Thrown when preflight finds an `error`-level problem. The SDK refuses to boot. */
export class PreflightError extends Error {
  constructor(readonly issues: PreflightIssue[]) {
    super(
      "[tetrac] Storage preflight failed — refusing to start:\n" +
        issues.map((i) => `  • [${i.code}] ${i.message}`).join("\n"),
    );
    this.name = "PreflightError";
  }
}

export interface CreateSqlAuthStoreOptions extends SqlAuthStoreOptions {
  /**
   * Skip the preflight checks. **Do not do this.** They exist because the failures they
   * catch are silent and catastrophic: a world-readable Supabase table, a MySQL instance
   * that truncates wallet blobs into oblivion, a SQLite file sitting under `public/`.
   * Prose does not stop those; a failed boot does.
   */
  skipPreflight?: boolean;
  /** Called with any `warn`-level findings. Defaults to `console.warn`. */
  onWarning?: (issue: PreflightIssue) => void;
}

/** Wire a driver + dialect into an AuthStore, running preflight first. */
export async function createSqlAuthStore(
  driver: SqlDriver,
  dialect: SqlDialect,
  opts: CreateSqlAuthStoreOptions = {},
): Promise<AuthStore & { sweepExpired(limit?: number): Promise<number>; close(): Promise<void> }> {
  if (!opts.skipPreflight) {
    const issues = await dialect.preflight(driver);
    const errors = issues.filter((i) => i.level === "error");
    if (errors.length) throw new PreflightError(errors);
    for (const w of issues.filter((i) => i.level === "warn")) {
      if (opts.onWarning) opts.onWarning(w);
      // eslint-disable-next-line no-console
      else console.warn(`[tetrac] ${w.code}: ${w.message}`);
    }
  }
  return new SqlAuthStore(driver, dialect, opts);
}

/**
 * PostgreSQL — and with it Supabase, Neon, RDS/Aurora, Railway, Render, Fly, and
 * CockroachDB. They all speak the Postgres wire protocol, so this one function covers them.
 *
 * Pass a `pg.Pool` (or anything structurally compatible: `@vercel/postgres`,
 * `@neondatabase/serverless`). Keep it a **module-level singleton** — a new pool per
 * request exhausts the server's connection limit, and that failure is a hard outage.
 */
export function createPostgresAuthStore(
  o: { client: PgLike } & PostgresDialectOptions & CreateSqlAuthStoreOptions,
) {
  return createSqlAuthStore(pgDriver(o.client), postgresDialect(o), o);
}

/**
 * MySQL / MariaDB. Pass a `mysql2/promise` **Pool** — not a single Connection: MySQL has no
 * `DELETE … RETURNING`, so atomic challenge-consume runs in a `SELECT … FOR UPDATE`
 * transaction, which needs a checked-out connection.
 */
export function createMysqlAuthStore(o: { client: MysqlLike } & CreateSqlAuthStoreOptions) {
  return createSqlAuthStore(mysqlDriver(o.client), mysqlDialect(), o);
}

/**
 * SQLite / libSQL. Dev, self-host, single-instance.
 *
 * ⚠️ It CANNOT back a serverless deployment — each instance would get its own private file,
 * so sessions neither persist nor replicate. Pass `path` so preflight can check the file's
 * permissions and that it isn't sitting somewhere your framework serves to the internet.
 */
export function createSqliteAuthStore(
  o: { client: SqliteLike } & SqliteDialectOptions & CreateSqlAuthStoreOptions,
) {
  return createSqlAuthStore(sqliteDriver(o.client), sqliteDialect(o), o);
}

/** The DDL for an engine. Emit it, run it, keep it in version control. */
export function schemaFor(
  engine: "postgres" | "mysql" | "sqlite",
  opts: PostgresDialectOptions = {},
): string {
  if (engine === "postgres") return postgresDialect(opts).ddl();
  if (engine === "mysql") return mysqlDialect().ddl();
  return sqliteDialect().ddl();
}

/**
 * The schema as individual statements.
 *
 * Piping `schemaFor()` into `psql` / the `mysql` CLI works fine — they understand comments
 * and multi-statement input. But a DRIVER usually does not: `mysql2` and `pg` reject
 * multi-statement queries by default, so people split the DDL on `;` themselves — and the
 * naive split glues the leading comment block onto the first `CREATE TABLE`, which then gets
 * dropped by a "skip comment lines" filter. The result is a database that is silently missing
 * its first table.
 *
 * (That is not hypothetical: it is exactly the bug this SDK's own MySQL test hit. Shipping the
 * correct split is cheaper than watching everyone rediscover it.)
 */
export function schemaStatementsFor(
  engine: "postgres" | "mysql" | "sqlite",
  opts: PostgresDialectOptions = {},
): string[] {
  return (
    schemaFor(engine, opts)
      .split("\n")
      // Strip EVERY `--` comment — whole-line AND trailing. Trailing matters more than it
      // looks: a comment like `-- epoch ms; filtered on every read` contains a SEMICOLON, and
      // splitting on `;` would shatter the CREATE TABLE in half. The halves then fail with an
      // opaque syntax error, or — worse on a `CREATE TABLE IF NOT EXISTS` — leave you with a
      // silently incomplete schema. (The SDK's DDL is comment-heavy on purpose; the column
      // types are load-bearing and deserve explaining. So the splitter has to be robust.)
      .map((line) => line.replace(/--.*$/, ""))
      .join("\n")
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}
