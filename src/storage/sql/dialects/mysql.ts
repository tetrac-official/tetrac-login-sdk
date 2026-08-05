// MySQL / MariaDB dialect.
//
// MySQL is the engine everyone warned about. It has three notorious hazards, and this
// file is the proof that ADR-002 works — because all three are solved HERE, in a dialect,
// and none of them are ever the integrator's problem:
//
//   1. NO `DELETE … RETURNING`. Atomic get-and-delete (the sole defense against challenge
//      REPLAY) is impossible in one statement. → We declare `supportsReturning: false` and
//      the engine transparently switches to a `SELECT … FOR UPDATE` + `DELETE` transaction.
//      One flag. The engine handles the rest.
//
//   2. The DEFAULT COLLATION IS CASE-INSENSITIVE (`utf8mb4_0900_ai_ci`). Under it, two
//      distinct base58 Solana addresses differing only in case map to the SAME row — and
//      tenants `Acme` and `acme` become the SAME namespace. → The DDL below uses
//      `VARBINARY` for every key column. Note that `utf8mb4_bin` would NOT be enough: it is
//      `PAD SPACE`, so 'k' and 'k ' still compare equal, including for PK uniqueness.
//
//   3. NON-STRICT MODE TRUNCATES SILENTLY instead of erroring. A truncated UserData blob is
//      invalid JSON, so the record reads back as null and the user is locked out of EVERY
//      wallet in it — with nothing anywhere pointing at the database. → `MEDIUMTEXT` for the
//      blob, and preflight REFUSES TO BOOT if strict mode is off.
import type { PreflightIssue, SqlDialect, SqlDriver, SqlTables } from "../types.js";

const tables: SqlTables = {
  users: "ttc_users",
  userWallets: "ttc_user_wallets",
  emailIndex: "ttc_email_index",
  sessions: "ttc_sessions",
  challenges: "ttc_challenges",
  rateLimits: "ttc_rate_limits",
};

export function mysqlDialect(): SqlDialect {
  return {
    name: "mysql",
    tables,
    // Hazard 1. This single flag is the entire cost of MySQL's missing RETURNING.
    supportsReturning: false,
    forUpdate: " FOR UPDATE",

    placeholder: () => "?",

    // MySQL ignores the conflict columns — it keys off whichever unique index is hit.
    upsert: (_conflictCols, setClauses) => `ON DUPLICATE KEY UPDATE ${setClauses.join(", ")}`,

    // MySQL DOES support DELETE … LIMIT, so no subquery needed. It reports affected rows.
    deleteExpiredLimited: (table, limit) =>
      `DELETE FROM ${table} WHERE expires_at <= ? LIMIT ${Math.max(1, limit | 0)}`,

    ddl: () => `
-- @tetrac/login-sdk — MySQL schema. Generated; do not hand-edit.
--
-- VARBINARY, not VARCHAR, for every key column. This is NOT stylistic:
--   • MySQL's default collation is CASE-INSENSITIVE, which would merge two distinct
--     Solana addresses (and two distinct tenants) into one row.
--   • utf8mb4_bin is NOT sufficient either — it is PAD SPACE, so 'k' and 'k ' compare
--     equal, including for PRIMARY KEY uniqueness.
-- VARBINARY compares bytes. Full stop.
--
-- MEDIUMTEXT, not TEXT, for the UserData blob: TEXT caps at 65,535 bytes and MySQL in
-- non-strict mode TRUNCATES SILENTLY. A truncated blob is invalid JSON ⇒ the record reads
-- back as null ⇒ the user is permanently locked out of every wallet in it.
-- (Preflight refuses to boot if strict mode is off.)

-- The data column is the PROFILE only; wallets are one row per slot below and the session pointer
-- is its own column, so no ordinary write rewrites this row wholesale.
CREATE TABLE IF NOT EXISTS ${tables.users} (
  app_id          VARBINARY(64)  NOT NULL,
  public_key      VARBINARY(128) NOT NULL,
  data            MEDIUMTEXT     NOT NULL,
  auth_token_hash VARBINARY(64)  NULL,
  PRIMARY KEY (app_id, public_key)
) ENGINE=InnoDB;

-- One row per (chain, role) slot — a slot write cannot disturb another slot.
-- Key columns are VARBINARY for the same reason as everywhere else here: MySQL default
-- collation is case-INSENSITIVE, which would collapse distinct values into one row.
CREATE TABLE IF NOT EXISTS ${tables.userWallets} (
  app_id      VARBINARY(64)  NOT NULL,
  public_key  VARBINARY(128) NOT NULL,
  chain       VARBINARY(16)  NOT NULL,
  role        VARBINARY(32)  NOT NULL,
  data        MEDIUMTEXT     NOT NULL,
  PRIMARY KEY (app_id, public_key, chain, role)
) ENGINE=InnoDB;

-- One ROW per (email, app) ⇒ concurrent registrations cannot lose a write.
CREATE TABLE IF NOT EXISTS ${tables.emailIndex} (
  email       VARBINARY(320) NOT NULL,
  app_id      VARBINARY(64)  NOT NULL,
  public_key  VARBINARY(128) NOT NULL,
  PRIMARY KEY (email, app_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ${tables.sessions} (
  app_id      VARBINARY(64)  NOT NULL,
  token_hash  VARBINARY(64)  NOT NULL,   -- SHA-256 hex of the bearer token. NEVER the token.
  public_key  VARBINARY(128) NOT NULL,
  fingerprint VARBINARY(128) NULL,
  expires_at  BIGINT         NOT NULL,   -- epoch ms; filtered on every read
  PRIMARY KEY (app_id, token_hash),
  KEY ttc_sessions_expires_idx (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ${tables.challenges} (
  app_id      VARBINARY(64)  NOT NULL,
  public_key  VARBINARY(128) NOT NULL,
  challenge   VARBINARY(128) NOT NULL,
  expires_at  BIGINT         NOT NULL,
  PRIMARY KEY (app_id, public_key),
  KEY ttc_challenges_expires_idx (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ${tables.rateLimits} (
  endpoint    VARBINARY(64)  NOT NULL,
  app_id      VARBINARY(64)  NOT NULL,   -- '' for the global client-IP bucket
  identifier  VARBINARY(320) NOT NULL,   -- an email or an IP — PII. Sweep it.
  count       BIGINT         NOT NULL,
  expires_at  BIGINT         NOT NULL,
  PRIMARY KEY (endpoint, app_id, identifier),
  KEY ttc_rate_limits_expires_idx (expires_at)
) ENGINE=InnoDB;
`,

    async preflight(driver: SqlDriver): Promise<PreflightIssue[]> {
      const issues: PreflightIssue[] = [];

      // Hazard 3. Silent truncation is an unrecoverable account. Refuse to boot.
      const mode = await driver.query<{ mode: string }>(`SELECT @@SESSION.sql_mode AS mode`, []);
      const sqlMode = String(mode[0]?.mode ?? "");
      if (!/STRICT_ALL_TABLES|STRICT_TRANS_TABLES/i.test(sqlMode)) {
        issues.push({
          level: "error",
          code: "not_strict_mode",
          message:
            "MySQL is NOT in strict mode. It would TRUNCATE over-long values SILENTLY rather " +
            "than erroring — and a truncated UserData blob is invalid JSON, so the record reads " +
            "back as null and the user is permanently locked out of every wallet in it, with " +
            "nothing pointing at the database. Set sql_mode to include STRICT_ALL_TABLES.",
        });
      }

      const rows = await driver.query<{ TABLE_NAME: string; table_name: string }>(
        `SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()`,
        [],
      );
      const found = new Set(rows.map((r) => String(r.TABLE_NAME ?? r.table_name)));
      const missing = Object.values(tables).filter((t) => !found.has(t));
      if (missing.length) {
        issues.push({
          level: "error",
          code: "missing_tables",
          message:
            `Missing table(s): ${missing.join(", ")}. ` +
            `Run the generated schema first (npx tetrac-db schema --mysql).`,
        });
        return issues; // the collation check below needs the tables to exist
      }

      // Hazard 2. If someone hand-rolled the schema with VARCHAR, their tenants and their
      // users are one bad collation away from merging. Catch it.
      const cols = await driver.query<{ TABLE_NAME: string; COLUMN_NAME: string; DATA_TYPE: string }>(
        `SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE
           FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME IN (?, ?, ?, ?, ?)
            AND COLUMN_NAME IN ('app_id','public_key','email','token_hash','identifier','endpoint','challenge')`,
        Object.values(tables),
      );
      const nonBinary = cols.filter((c) => !/binary|blob/i.test(String(c.DATA_TYPE)));
      if (nonBinary.length) {
        issues.push({
          level: "error",
          code: "non_binary_key_columns",
          message:
            `These key columns are not binary: ` +
            nonBinary.map((c) => `${c.TABLE_NAME}.${c.COLUMN_NAME}`).join(", ") +
            `. Under MySQL's default (case-INSENSITIVE) collation, two distinct base58 public ` +
            `keys — or two distinct tenants ('Acme' vs 'acme') — collapse into the SAME row. ` +
            `Use the generated schema (VARBINARY). Note utf8mb4_bin is NOT enough: it is PAD ` +
            `SPACE, so 'k' and 'k ' still collide.`,
        });
      }

      return issues;
    },
  };
}
