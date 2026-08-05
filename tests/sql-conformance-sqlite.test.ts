// ADR-002 — the SQL engine, verified against a REAL SQL engine.
//
// This is the proof that the architecture works. `SqlAuthStore` is where every correctness
// rule now lives (expiry-on-read, the rate-limit window, atomic challenge consume, no lost
// write on the email index, normalizeEmail, injection safety). If it is right, then Postgres,
// SQLite, and MySQL are all right — because they share this code and differ only in a dialect.
//
// SQLite is a genuine SQL engine with real transactions and a real query planner, and it runs
// in-process with zero infrastructure. So the whole suite runs here on every `npm test`, on
// every Node version, with no Docker. Postgres runs the same suite in CI (sql-conformance-
// postgres.test.ts) to prove the dialect abstraction holds across engines.
import Database from "better-sqlite3";
import { authStoreConformanceCases } from "../src/storage/conformance";
import { SqlAuthStore } from "../src/storage/sql/engine";
import { sqliteDriver } from "../src/storage/sql/drivers";
import { sqliteDialect } from "../src/storage/sql/dialects/sqlite";
import { createSqliteAuthStore, PreflightError, schemaFor, schemaStatementsFor } from "../src/storage/sql";

// One mutable clock the suite drives via `advance`. The engine takes an injectable `now`,
// so expiry is tested exactly — no sleeping, no flakiness.
const T0 = 1_700_000_000_000;
let now = T0;

function freshStore(): SqlAuthStore {
  now = T0;
  const db = new Database(":memory:");
  db.exec(sqliteDialect().ddl());
  return new SqlAuthStore(sqliteDriver(db as never), sqliteDialect(), { now: () => now });
}

describe("ADR-002 — AuthStore conformance: SqlAuthStore on a REAL SQLite engine", () => {
  const cases = authStoreConformanceCases(freshStore, {
    advance: (ms) => {
      now += ms;
    },
    supportsSweep: true,
  });

  it("exposes the full case list", () => {
    expect(cases.length).toBeGreaterThanOrEqual(18);
  });

  for (const c of cases) {
    it(c.name, () => c.run());
  }
});

describe("ADR-002 — the SDK owns the schema, so the integrator cannot get it wrong", () => {
  it("emits DDL for every engine", () => {
    for (const engine of ["postgres", "mysql", "sqlite"] as const) {
      const ddl = schemaFor(engine);
      expect(ddl).toContain("ttc_sessions");
      expect(ddl).toContain("ttc_email_index");
      // The email index is keyed (email, app_id) — ONE ROW per tenant. That is what makes a
      // lost write structurally impossible rather than merely avoided.
      expect(ddl).toMatch(/PRIMARY KEY \(email, app_id\)/i);
    }
  });

  it("🚨 MySQL's DDL uses VARBINARY keys and MEDIUMTEXT — the three MySQL hazards, solved in a dialect", () => {
    // Assert on the STATEMENTS, not the explanatory comments (which legitimately mention the
    // traps by name).
    const sql = schemaFor("mysql")
      .split("\n")
      .filter((l) => !l.trim().startsWith("--"))
      .join("\n");

    // Case-insensitive collation would merge two distinct Solana addresses — and two tenants.
    expect(sql).toMatch(/app_id\s+VARBINARY/i);
    expect(sql).toMatch(/public_key\s+VARBINARY/i);
    expect(sql).toMatch(/token_hash\s+VARBINARY/i);
    // utf8mb4_bin is NOT sufficient (it is PAD SPACE: 'k' and 'k ' still collide), so no key
    // column may fall back to a character type at all.
    expect(sql).not.toMatch(/utf8mb4_bin/i);
    expect(sql).not.toMatch(/(app_id|public_key|email|token_hash)\s+VARCHAR/i);
    // TEXT (65,535 B) + non-strict mode = silent truncation = permanent wallet lockout.
    expect(sql).toMatch(/data\s+MEDIUMTEXT/i);
    expect(sql).not.toMatch(/data\s+TEXT/i);
  });

  it("Postgres DDL never uses the `public` schema", () => {
    const ddl = schemaFor("postgres");
    expect(ddl).toContain("CREATE SCHEMA IF NOT EXISTS tetrac");
    expect(ddl).not.toMatch(/public\.ttc_/);
  });

  // Regression: the DDL's inline comments contain SEMICOLONS ("-- epoch ms; filtered on every
  // read"). A naive `.split(";")` shatters the CREATE TABLE in half — and because the halves
  // are `CREATE TABLE IF NOT EXISTS`, you can end up with a SILENTLY INCOMPLETE schema rather
  // than a loud failure. Found by running MySQL for real; it affected all three dialects.
  it("🚨 schemaStatementsFor survives semicolons inside DDL comments", () => {
    for (const engine of ["postgres", "mysql", "sqlite"] as const) {
      const stmts = schemaStatementsFor(engine);

      // 5 tables (+ indexes, + CREATE SCHEMA on Postgres). Every statement must be complete.
      expect(stmts.length).toBeGreaterThanOrEqual(5);
      for (const s of stmts) {
        expect(s).not.toContain("--"); // no comment fragments survived
        const opens = (s.match(/\(/g) ?? []).length;
        const closes = (s.match(/\)/g) ?? []).length;
        expect({ engine, s, balanced: opens === closes }).toEqual({ engine, s, balanced: true });
      }

      // And all five tables are actually created — not just the ones before the first `;`-in-comment.
      const joined = stmts.join("\n");
      for (const table of [
        "ttc_users",
        "ttc_email_index",
        "ttc_sessions",
        "ttc_challenges",
        "ttc_rate_limits",
      ]) {
        expect(joined).toContain(table);
      }
    }
  });
});

describe("ADR-002 — preflight REFUSES TO BOOT on the silent, catastrophic misconfigurations", () => {
  it("🚨 refuses to start when the schema was never created", async () => {
    const db = new Database(":memory:"); // no DDL run
    await expect(createSqliteAuthStore({ client: db as never })).rejects.toThrow(PreflightError);
    await expect(createSqliteAuthStore({ client: db as never })).rejects.toThrow(/missing table/i);
  });

  it("🚨 refuses a database file sitting under a web-served directory", async () => {
    const db = new Database(":memory:");
    db.exec(sqliteDialect().ddl());
    // `public/auth.db` is a ONE-REQUEST DOWNLOAD of the entire auth store — session records
    // and every user's encrypted wallet blob — with no vulnerability required, just a URL.
    await expect(
      createSqliteAuthStore({ client: db as never, path: "/srv/app/public/auth.db" }),
    ).rejects.toThrow(/web-served/i);
  });

  it("boots cleanly once the schema exists", async () => {
    const db = new Database(":memory:");
    db.exec(sqliteDialect().ddl());
    const store = await createSqliteAuthStore({ client: db as never });
    expect(typeof store.hitRateLimit).toBe("function");
    await store.close();
  });

  it("skipPreflight is possible but never the default", async () => {
    const db = new Database(":memory:"); // deliberately no schema
    const store = await createSqliteAuthStore({ client: db as never, skipPreflight: true });
    expect(store).toBeDefined();
  });
});
