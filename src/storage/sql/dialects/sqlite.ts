// SQLite dialect. Dev, self-host, single-instance — and libSQL/Turso.
//
// ⚠️ A SQLite file CANNOT back a serverless deployment: each instance would get its own
// private store, so sessions neither persist nor replicate. And the file IS a credential
// store — preflight checks its permissions and its path (see below).
import { statSync } from "node:fs";
import type { PreflightIssue, SqlDialect, SqlDriver, SqlTables } from "../types.js";

export interface SqliteDialectOptions {
  /** Path to the database file, so preflight can check its mode and location. */
  path?: string;
}

const tables: SqlTables = {
  users: "ttc_users",
  userWallets: "ttc_user_wallets",
  emailIndex: "ttc_email_index",
  sessions: "ttc_sessions",
  challenges: "ttc_challenges",
  rateLimits: "ttc_rate_limits",
};

/** Directories a framework serves verbatim. A DB file here is a one-request download of
 *  the entire auth store — no vulnerability required, just a URL. */
const WEB_SERVED = ["/public/", "/static/", "/www/", "/dist/", "/.next/static/"];

export function sqliteDialect(opts: SqliteDialectOptions = {}): SqlDialect {
  return {
    name: "sqlite",
    tables,
    // DELETE … RETURNING landed in SQLite 3.35 (2021). better-sqlite3 bundles a modern build.
    supportsReturning: true,
    // SQLite serializes writers, so an explicit row lock is neither available nor needed.
    forUpdate: "",

    placeholder: () => "?",

    upsert: (conflictCols, setClauses) =>
      `ON CONFLICT (${conflictCols.join(", ")}) DO UPDATE SET ${setClauses.join(", ")}`,

    deleteExpiredLimited: (table, limit) =>
      `DELETE FROM ${table} WHERE rowid IN (` +
      `SELECT rowid FROM ${table} WHERE expires_at <= ? LIMIT ${Math.max(1, limit | 0)}` +
      `) RETURNING 1 AS affected`,

    ddl: () => `
-- @tetrac/login-sdk — SQLite schema. Generated; do not hand-edit.
-- SQLite's default collation is BINARY, so keys compare byte-exactly and 'Acme' ≠ 'acme'.
-- NEVER declare these columns COLLATE NOCASE: it would merge distinct public keys and
-- distinct tenants into one row.

-- The data column is the PROFILE only; wallets are one row per slot below and the session pointer
-- is its own column, so no ordinary write rewrites this row wholesale.
CREATE TABLE IF NOT EXISTS ${tables.users} (
  app_id          TEXT NOT NULL,
  public_key      TEXT NOT NULL,
  data            TEXT NOT NULL,
  auth_token_hash TEXT,
  PRIMARY KEY (app_id, public_key)
);

-- One row per (chain, role) slot — a slot write cannot disturb another slot.
CREATE TABLE IF NOT EXISTS ${tables.userWallets} (
  app_id      TEXT NOT NULL,
  public_key  TEXT NOT NULL,
  chain       TEXT NOT NULL,
  role        TEXT NOT NULL,
  data        TEXT NOT NULL,
  PRIMARY KEY (app_id, public_key, chain, role)
);

-- One ROW per (email, app) ⇒ concurrent registrations cannot lose a write.
CREATE TABLE IF NOT EXISTS ${tables.emailIndex} (
  email       TEXT NOT NULL,
  app_id      TEXT NOT NULL,
  public_key  TEXT NOT NULL,
  PRIMARY KEY (email, app_id)
);

CREATE TABLE IF NOT EXISTS ${tables.sessions} (
  app_id      TEXT NOT NULL,
  token_hash  TEXT NOT NULL,      -- SHA-256 of the bearer token. NEVER the token.
  public_key  TEXT NOT NULL,
  fingerprint TEXT,
  expires_at  INTEGER NOT NULL,   -- epoch ms; filtered on every read
  PRIMARY KEY (app_id, token_hash)
);

CREATE TABLE IF NOT EXISTS ${tables.challenges} (
  app_id      TEXT NOT NULL,
  public_key  TEXT NOT NULL,
  challenge   TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (app_id, public_key)
);

CREATE TABLE IF NOT EXISTS ${tables.rateLimits} (
  endpoint    TEXT NOT NULL,
  app_id      TEXT NOT NULL,      -- '' for the global client-IP bucket
  identifier  TEXT NOT NULL,      -- an email or an IP — PII. Sweep it.
  count       INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (endpoint, app_id, identifier)
);

CREATE INDEX IF NOT EXISTS ttc_sessions_expires_idx    ON ${tables.sessions}    (expires_at);
CREATE INDEX IF NOT EXISTS ttc_challenges_expires_idx  ON ${tables.challenges}  (expires_at);
CREATE INDEX IF NOT EXISTS ttc_rate_limits_expires_idx ON ${tables.rateLimits}  (expires_at);
`,

    async preflight(driver: SqlDriver): Promise<PreflightIssue[]> {
      const issues: PreflightIssue[] = [];

      const rows = await driver.query<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table'`,
        [],
      );
      const found = new Set(rows.map((r) => r.name));
      const missing = Object.values(tables).filter((t) => !found.has(t));
      if (missing.length) {
        issues.push({
          level: "error",
          code: "missing_tables",
          message: `Missing table(s): ${missing.join(", ")}. Run the generated schema first.`,
        });
      }

      // The file is a credential store — session records and encrypted wallet blobs.
      if (opts.path) {
        const normalized = opts.path.replace(/\\/g, "/");
        if (WEB_SERVED.some((d) => normalized.includes(d))) {
          issues.push({
            level: "error",
            code: "web_served_path",
            message:
              `The database file sits under a web-served directory (${opts.path}). That is a ` +
              `ONE-REQUEST DOWNLOAD of your entire auth store — session records and every ` +
              `user's encrypted wallet blob — with no vulnerability required. Move it outside ` +
              `the served tree (and its -wal / -shm sidecars with it).`,
          });
        }
        try {
          const mode = statSync(opts.path).mode & 0o777;
          if (mode & 0o077) {
            issues.push({
              level: "warn",
              code: "file_permissions",
              message:
                `The database file is mode 0${mode.toString(8)} — readable by other users on ` +
                `this host. It holds session records and encrypted wallet blobs. chmod 600 it ` +
                `(and its -wal / -shm sidecars).`,
            });
          }
        } catch {
          // File not created yet — nothing to check.
        }
      }

      return issues;
    },
  };
}
