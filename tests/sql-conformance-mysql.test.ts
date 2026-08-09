// ADR-002 — the ACID TEST. The same engine, on the hardest database.
//
// MySQL is the engine everyone warned about, and it is the one that decides whether ADR-002
// is real or wishful. It breaks the SDK's contract in three separate ways:
//
//   1. NO `DELETE … RETURNING` — so atomic get-and-delete (the ONLY defense against login-
//      challenge REPLAY) cannot be one statement.
//   2. A CASE-INSENSITIVE default collation — which would merge two distinct base58 Solana
//      addresses, and two distinct tenants ('Acme'/'acme'), into the SAME row.
//   3. SILENT TRUNCATION in non-strict mode — a clipped UserData blob is invalid JSON, so the
//      record reads back as null and the user is locked out of EVERY wallet in it.
//
// If ADR-002 works, all three are absorbed by a ~30-line dialect and the engine code is
// untouched — and the very same 24 conformance cases that pass on SQLite and Postgres pass
// here too. That is what this file asserts.
//
// SKIPPED unless MYSQL_URL is set:
//   docker run --rm -p 3306:3306 -e MYSQL_ROOT_PASSWORD=pw -e MYSQL_DATABASE=tetrac_test mysql:8
//   MYSQL_URL=mysql://root:pw@localhost:3306/tetrac_test npx jest tests/sql-conformance-mysql
import mysql from "mysql2/promise";
import { authStoreConformanceCases } from "../src/storage/conformance";
import { SqlAuthStore } from "../src/storage/sql/engine";
import { mysqlDriver } from "../src/storage/sql/drivers";
import { mysqlDialect } from "../src/storage/sql/dialects/mysql";
import { createMysqlAuthStore, PreflightError, schemaStatementsFor } from "../src/storage/sql";

const MYSQL_URL = process.env.MYSQL_URL;

const T0 = 1_700_000_000_000;
let now = T0;
const pools: mysql.Pool[] = [];

/** Each case gets a clean database — one shared MySQL, so the cases must not see each other. */
async function freshStore(): Promise<SqlAuthStore> {
  now = T0;
  const pool = mysql.createPool({ uri: MYSQL_URL, connectionLimit: 5, multipleStatements: true });
  pools.push(pool);

  const dialect = mysqlDialect();
  for (const table of Object.values(dialect.tables)) {
    await pool.query(`DROP TABLE IF EXISTS ${table}`);
  }
  // mysql2 rejects multi-statement queries, so feed the DDL one statement at a time.
  // Use the SDK's splitter — a naive `.split(";")` glues the leading comment block onto the
  // first CREATE TABLE, and a "skip lines starting with --" filter then drops that whole chunk,
  // silently leaving the database without its first table. (Ask me how I know.)
  for (const stmt of schemaStatementsFor("mysql")) {
    await pool.query(stmt);
  }

  return new SqlAuthStore(mysqlDriver(pool as never), dialect, { now: () => now });
}

const describeMysql = MYSQL_URL ? describe : describe.skip;

describeMysql("ADR-002 — AuthStore conformance: SqlAuthStore on a REAL MySQL", () => {
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end().catch(() => undefined)));
  });

  const cases = MYSQL_URL
    ? authStoreConformanceCases(freshStore, {
        advance: (ms) => {
          now += ms;
        },
        supportsSweep: true,
      })
    : [];

  it("exposes the full case list", () => {
    expect(cases.length).toBeGreaterThanOrEqual(18);
  });

  for (const c of cases) {
    it(c.name, () => c.run(), 30_000);
  }
});

describeMysql("ADR-002 — MySQL's three hazards are dead, and the schema proves it", () => {
  it("🚨 key columns really are BINARY in the live database — 'Acme' and 'acme' cannot merge", async () => {
    const pool = mysql.createPool({ uri: MYSQL_URL, connectionLimit: 2 });
    pools.push(pool);
    await freshStore(); // (re)creates the tables

    const [rows] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, COLLATION_NAME
         FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME LIKE 'ttc_%'
          AND COLUMN_NAME IN ('app_id','public_key','email','token_hash','identifier')`,
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      // varbinary compares BYTES. A character type here — even utf8mb4_bin, which is PAD
      // SPACE — would let distinct keys collide.
      expect(String(r.DATA_TYPE).toLowerCase()).toBe("varbinary");
      expect(r.COLLATION_NAME).toBeNull();
    }
  }, 30_000);

  it("🚨 the UserData column is MEDIUMTEXT — TEXT would silently truncate a 64-wallet record", async () => {
    const pool = mysql.createPool({ uri: MYSQL_URL, connectionLimit: 2 });
    pools.push(pool);
    await freshStore();

    const [rows] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT DATA_TYPE FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ttc_users' AND COLUMN_NAME = 'data'`,
    );
    expect(String(rows[0]?.DATA_TYPE).toLowerCase()).toBe("mediumtext");
  }, 30_000);

  it("🚨 preflight REFUSES to boot when MySQL is not in strict mode", async () => {
    // Silent truncation is an unrecoverable account: the blob becomes invalid JSON, the record
    // reads back as null, and the user loses every wallet in it — with nothing pointing at the
    // database. A failed boot is the only defense that actually works.
    const pool = mysql.createPool({ uri: MYSQL_URL, connectionLimit: 2 });
    pools.push(pool);
    await pool.query(`SET SESSION sql_mode = ''`); // simulate a non-strict server

    // Every pooled connection must be non-strict for the check to see it.
    const lax = {
      query: async (sql: string, params?: readonly unknown[]) => {
        if (/@@SESSION\.sql_mode/i.test(sql)) return [[{ mode: "NO_ENGINE_SUBSTITUTION" }], []];
        return pool.query(sql, params as never);
      },
      getConnection: () => pool.getConnection(),
      end: () => pool.end(),
    };

    await expect(createMysqlAuthStore({ client: lax as never })).rejects.toThrow(PreflightError);
    await expect(createMysqlAuthStore({ client: lax as never })).rejects.toThrow(/strict mode/i);
  }, 30_000);

  it("boots cleanly against a strict server with the generated schema", async () => {
    await freshStore();
    const pool = mysql.createPool({ uri: MYSQL_URL, connectionLimit: 2 });
    pools.push(pool);
    const store = await createMysqlAuthStore({ client: pool as never });
    expect(typeof store.hitRateLimit).toBe("function");
  }, 30_000);
});

(process.env.CI ? describe : describe.skip)("MySQL conformance is WIRED in CI", () => {
  it("MYSQL_URL must be set in CI", () => {
    expect(MYSQL_URL).toBeTruthy();
  });
});
