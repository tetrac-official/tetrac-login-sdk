// ADR-002 — the SAME conformance suite, the SAME engine code, a DIFFERENT database.
//
// sql-conformance-sqlite.test.ts proves `SqlAuthStore` is correct. This file proves the
// DIALECT ABSTRACTION holds: swap `sqliteDialect()` for `postgresDialect()` — a different
// placeholder syntax, a different upsert clause, a different DELETE…LIMIT — and every one of
// the 24 cases still passes, with **zero changes to the engine**.
//
// That is the entire claim of ADR-002, tested. If it holds here, then adding MySQL really is
// ~30 lines of dialect rather than a security review.
//
// SKIPPED unless POSTGRES_URL is set, so `npm test` stays green on a laptop with no Docker:
//   docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:16-alpine
//   POSTGRES_URL=postgres://postgres:pw@localhost:5432/postgres npx jest tests/sql-conformance-postgres
// CI sets it via a `postgres:16-alpine` service container.
import { Pool } from "pg";
import { authStoreConformanceCases } from "../src/storage/conformance";
import { SqlAuthStore } from "../src/storage/sql/engine";
import { pgDriver } from "../src/storage/sql/drivers";
import { postgresDialect } from "../src/storage/sql/dialects/postgres";
import type { SqlDriver } from "../src/storage/sql/types";
import { createPostgresAuthStore, PreflightError } from "../src/storage/sql";

const POSTGRES_URL = process.env.POSTGRES_URL;

// The fail-closed cases need a store whose backend FAILS every query — no real connection
// required, since the point is that the shared engine propagates the error rather than
// swallowing it. The dialect is irrelevant here (nothing reaches the DB).
function failingStore(): SqlAuthStore {
  const driver: SqlDriver = {
    query: () => Promise.reject(new Error("backend unavailable (connection reset)")),
    transaction: () => Promise.reject(new Error("backend unavailable (connection reset)")),
  };
  return new SqlAuthStore(driver, postgresDialect({ schema: "conf_fail" }));
}

const T0 = 1_700_000_000_000;
let now = T0;

// Each case gets its own schema, so the 24 cases cannot see each other's rows.
let n = 0;
const pools: Pool[] = [];

async function freshStore(): Promise<SqlAuthStore> {
  now = T0;
  const schema = `conf_${++n}_${process.pid}`;
  const pool = new Pool({ connectionString: POSTGRES_URL, max: 4 });
  pools.push(pool);

  const dialect = postgresDialect({ schema });
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(dialect.ddl());

  return new SqlAuthStore(pgDriver(pool as never), dialect, { now: () => now });
}

const describePg = POSTGRES_URL ? describe : describe.skip;

describePg("ADR-002 — AuthStore conformance: SqlAuthStore on a REAL Postgres", () => {
  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end().catch(() => undefined)));
  });

  const cases = POSTGRES_URL
    ? authStoreConformanceCases(freshStore, {
        advance: (ms) => {
          now += ms;
        },
        supportsSweep: true,
        makeFailingStore: failingStore,
      })
    : [];

  it("exposes the full case list", () => {
    expect(cases.length).toBeGreaterThanOrEqual(18);
  });

  for (const c of cases) {
    it(c.name, () => c.run(), 30_000);
  }
});

describePg("ADR-002 — Postgres preflight", () => {
  it("🚨 REFUSES the `public` schema — on Supabase that table is served to the internet", async () => {
    const pool = new Pool({ connectionString: POSTGRES_URL, max: 2 });
    pools.push(pool);
    // Supabase auto-generates a PostgREST API over every table in `public`, served to anyone
    // holding the browser-shipped `anon` key. These tables hold session records and every
    // user's encrypted wallet blob. A failed boot is the only defense that actually works.
    await expect(createPostgresAuthStore({ client: pool as never, schema: "public" })).rejects.toThrow(
      PreflightError,
    );
    await expect(createPostgresAuthStore({ client: pool as never, schema: "public" })).rejects.toThrow(
      /public.*schema|world-readable/i,
    );
  }, 30_000);

  it("refuses to start when the schema was never created", async () => {
    const pool = new Pool({ connectionString: POSTGRES_URL, max: 2 });
    pools.push(pool);
    await expect(
      createPostgresAuthStore({ client: pool as never, schema: "definitely_not_created" }),
    ).rejects.toThrow(/missing table/i);
  }, 30_000);
});

// A skipped suite is not a passing suite: if the CI service breaks, fail loudly rather than
// silently testing nothing.
(process.env.CI ? describe : describe.skip)("Postgres conformance is WIRED in CI", () => {
  it("POSTGRES_URL must be set in CI", () => {
    expect(POSTGRES_URL).toBeTruthy();
  });
});
