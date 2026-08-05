// Postgres dialect. Covers Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly,
// and CockroachDB — they all speak the Postgres wire protocol.
import type { PreflightIssue, SqlDialect, SqlDriver, SqlTables } from "../types.js";

export interface PostgresDialectOptions {
  /**
   * Schema for the SDK's tables. Defaults to `tetrac` — deliberately NOT `public`.
   *
   * On Supabase, `public` is served over PostgREST to anyone holding the browser-shipped
   * `anon` key, so tables there are WORLD-READABLE — and these tables hold session records
   * and every user's encrypted wallet blob. Preflight refuses to boot on `public` unless
   * you explicitly opt in.
   */
  schema?: string;
  /** Escape hatch for the `public`-schema guard. You almost certainly do not want this. */
  allowPublicSchema?: boolean;
}

export function postgresDialect(opts: PostgresDialectOptions = {}): SqlDialect {
  const schema = opts.schema ?? "tetrac";
  const q = (name: string): string => `${schema}.${name}`;

  const tables: SqlTables = {
    users: q("ttc_users"),
    userWallets: q("ttc_user_wallets"),
    emailIndex: q("ttc_email_index"),
    sessions: q("ttc_sessions"),
    challenges: q("ttc_challenges"),
    rateLimits: q("ttc_rate_limits"),
  };

  return {
    name: "postgres",
    tables,
    supportsReturning: true,
    forUpdate: " FOR UPDATE",

    placeholder: (i) => `$${i + 1}`,

    upsert: (conflictCols, setClauses) =>
      `ON CONFLICT (${conflictCols.join(", ")}) DO UPDATE SET ${setClauses.join(", ")}`,

    // Postgres has no `DELETE … LIMIT`, hence the ctid subquery. RETURNING lets the engine
    // count what it removed.
    deleteExpiredLimited: (table, limit) =>
      `DELETE FROM ${table} WHERE ctid IN (` +
      `SELECT ctid FROM ${table} WHERE expires_at <= $1 LIMIT ${Math.max(1, limit | 0)}` +
      `) RETURNING 1 AS affected`,

    ddl: () => `
-- @tetrac/login-sdk — Postgres schema. Generated; do not hand-edit.
-- The column types and keys here are LOAD-BEARING (ADR-002): they are what make lost
-- writes, collation collisions, and silent truncation structurally impossible.

CREATE SCHEMA IF NOT EXISTS ${schema};

-- Postgres's default collation is deterministic, so text keys compare byte-exactly and
-- 'Acme' ≠ 'acme'. (That is NOT true of MySQL — see the MySQL dialect.)
-- The data column is the PROFILE only. Wallets live one row per slot below, and the session
-- pointer is its own column, so no ordinary write rewrites this row wholesale.
CREATE TABLE IF NOT EXISTS ${tables.users} (
  app_id          text NOT NULL,
  public_key      text NOT NULL,
  data            text NOT NULL,       -- UserData minus wallets/authTokenHash
  auth_token_hash text,                -- SHA-256 of the current session token
  PRIMARY KEY (app_id, public_key)
);

-- One row per (chain, role) slot. This is what makes an import a single-row write that
-- cannot lose a concurrent wallet write or be lost by a concurrent login.
CREATE TABLE IF NOT EXISTS ${tables.userWallets} (
  app_id      text NOT NULL,
  public_key  text NOT NULL,
  chain       text NOT NULL,
  role        text NOT NULL,
  data        text NOT NULL,           -- one EncryptedWallet as JSON
  PRIMARY KEY (app_id, public_key, chain, role)
);

-- One ROW per (email, app) — NOT one row with a field per tenant. This is what makes two
-- concurrent registrations of the same email under different appIds unable to lose a write.
CREATE TABLE IF NOT EXISTS ${tables.emailIndex} (
  email       text NOT NULL,           -- always normalizeEmail()'d by the engine
  app_id      text NOT NULL,
  public_key  text NOT NULL,
  PRIMARY KEY (email, app_id)
);

CREATE TABLE IF NOT EXISTS ${tables.sessions} (
  app_id      text NOT NULL,
  token_hash  text NOT NULL,           -- SHA-256 of the bearer token. NEVER the token.
  public_key  text NOT NULL,
  fingerprint text,                    -- typed column, not a "pk|fp" string
  expires_at  bigint NOT NULL,         -- epoch ms; filtered on every read
  PRIMARY KEY (app_id, token_hash)
);

CREATE TABLE IF NOT EXISTS ${tables.challenges} (
  app_id      text NOT NULL,
  public_key  text NOT NULL,
  challenge   text NOT NULL,
  expires_at  bigint NOT NULL,
  PRIMARY KEY (app_id, public_key)
);

CREATE TABLE IF NOT EXISTS ${tables.rateLimits} (
  endpoint    text NOT NULL,
  app_id      text NOT NULL,           -- '' for the global client-IP bucket
  identifier  text NOT NULL,           -- an email or an IP — this is PII. Sweep it.
  count       bigint NOT NULL,
  expires_at  bigint NOT NULL,
  PRIMARY KEY (endpoint, app_id, identifier)
);

CREATE INDEX IF NOT EXISTS ttc_sessions_expires_idx    ON ${tables.sessions}    (expires_at);
CREATE INDEX IF NOT EXISTS ttc_challenges_expires_idx  ON ${tables.challenges}  (expires_at);
CREATE INDEX IF NOT EXISTS ttc_rate_limits_expires_idx ON ${tables.rateLimits}  (expires_at);
`,

    async preflight(driver: SqlDriver): Promise<PreflightIssue[]> {
      const issues: PreflightIssue[] = [];

      // 🚨 The highest-severity misconfiguration available, and it is INVISIBLE from the
      // app side — everything works perfectly while the table is served to the internet.
      if (schema === "public" && !opts.allowPublicSchema) {
        issues.push({
          level: "error",
          code: "public_schema",
          message:
            "Refusing to use the `public` schema for auth tables. On Supabase, `public` is " +
            "exposed over PostgREST to anyone holding the browser-shipped `anon` key — these " +
            "tables would be WORLD-READABLE, and they hold session records and every user's " +
            "encrypted wallet blob. Use the default `tetrac` schema. If this is definitely not " +
            "Supabase and you accept the risk, pass allowPublicSchema: true.",
        });
      }

      const rows = await driver.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = $1`,
        [schema],
      );
      const found = new Set(rows.map((r) => r.table_name));
      const missing = Object.values(tables)
        .map((t) => t.split(".").pop() as string)
        .filter((t) => !found.has(t));
      if (missing.length) {
        issues.push({
          level: "error",
          code: "missing_tables",
          message:
            `Missing table(s) in schema "${schema}": ${missing.join(", ")}. ` +
            `Run the generated schema first (npx tetrac-db schema --postgres).`,
        });
      }

      // A NONDETERMINISTIC collation can equate distinct byte strings for uniqueness — the
      // same failure as MySQL's case-insensitive default, which would merge two distinct
      // Solana addresses (or two tenants) into one row.
      //
      // This is a WARN, and it is wrapped: a diagnostic that cannot run must not take the
      // process down with it. Preflight refusing to boot is a security feature; preflight
      // refusing to boot because its own introspection query failed on some managed variant
      // is an outage. Errors are reserved for things we actually proved are wrong.
      try {
        const coll = await driver.query<{ nondeterministic: number | string }>(
          `SELECT count(*) AS nondeterministic
             FROM pg_collation c
             JOIN pg_database d ON d.datcollate = c.collcollate
            WHERE d.datname = current_database() AND NOT c.collisdeterministic`,
          [],
        );
        if (Number(coll[0]?.nondeterministic ?? 0) > 0) {
          issues.push({
            level: "warn",
            code: "nondeterministic_collation",
            message:
              "This database appears to use a NONDETERMINISTIC collation. Distinct byte strings " +
              "may compare equal, which can merge two distinct public keys — or two tenants — " +
              "into one row. Use a deterministic (C / default) collation.",
          });
        }
      } catch {
        // Introspection unavailable (some managed/pooled setups). Not a reason to fail closed.
      }

      return issues;
    },
  };
}
