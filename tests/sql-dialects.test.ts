// ADR-002 — dialect-level invariants, checked WITHOUT a database.
//
// The Postgres/MySQL conformance runs need real engines (CI). But the bug class most likely
// to break Postgres while SQLite passes needs no database at all to catch: **placeholder /
// parameter mismatch**. SQLite and MySQL use `?`; Postgres uses `$1…$n`. If the engine ever
// emits a different number of placeholders than it binds parameters, Postgres fails at
// runtime while SQLite silently... also fails, but only under the right shape of input.
//
// So: run every AuthStore method against every dialect through a RECORDING driver, and assert
// two things that must hold universally —
//
//   1. placeholder count == bound-parameter count, in every statement, in every dialect.
//   2. NO parameter value ever appears inside the SQL text. That is an injection test at the
//      engine level: it proves values are BOUND, not interpolated — for all engines at once,
//      and it cannot be fooled by an escaping bug.
import { SqlAuthStore } from "../src/storage/sql/engine";
import { postgresDialect } from "../src/storage/sql/dialects/postgres";
import { mysqlDialect } from "../src/storage/sql/dialects/mysql";
import { sqliteDialect } from "../src/storage/sql/dialects/sqlite";
import type { SqlDialect, SqlDriver } from "../src/storage/sql/types";
import type { UserData } from "../src/core/types";

interface Recorded {
  sql: string;
  params: readonly unknown[];
}

function recordingDriver(log: Recorded[]): SqlDriver {
  const driver: SqlDriver = {
    async query<T>(sql: string, params: readonly unknown[]): Promise<T[]> {
      log.push({ sql, params });
      return [] as T[];
    },
    transaction: (fn) => fn(driver),
  };
  return driver;
}

const DIALECTS: [string, SqlDialect][] = [
  ["postgres", postgresDialect()],
  ["mysql", mysqlDialect()],
  ["sqlite", sqliteDialect()],
];

/** Values chosen to be hostile: SQL metacharacters, quotes, and a NoSQL operator shape. */
const NASTY = `' OR 1=1 --`;
const NASTY2 = `{"$gt":""}`;

/** A realistic session-token digest (the SDK passes a 64-hex SHA-256).
 *  Deliberately NOT the literal "hash": that is a substring of the column name `token_hash`,
 *  which would make the interpolation assertion below fire as a false positive. */
const TOKEN_HASH = "a1b2c3d4".repeat(8);

const user: UserData = {
  appId: "app1",
  publicKey: NASTY,
  email: "  MiXeD@Example.COM ",
  authMethod: "email",
  wallets: [],
  createdAt: 1,
} as UserData;

/** Exercise every method that touches the database. */
async function exerciseAll(store: SqlAuthStore): Promise<void> {
  await store.getUser("app1", NASTY);
  await store.putUser(user);
  await store.getPublicKeyByEmail("app1", NASTY2);
  await store.putChallenge("app1", NASTY, NASTY2, 300);
  await store.takeChallenge("app1", NASTY);
  await store.putSession("app1", TOKEN_HASH, { publicKey: NASTY, fingerprint: NASTY2 }, 300);
  await store.getSession("app1", TOKEN_HASH);
  await store.deleteSession("app1", TOKEN_HASH);
  await store.hitRateLimit({ endpoint: "login", appId: "app1", identifier: NASTY }, 60, 5);
  await store.hitRateLimit({ endpoint: "ip", identifier: NASTY2 }, 60, 5); // no appId — the global IP bucket
  await store.sweepExpired(10);
}

describe.each(DIALECTS)("ADR-002 — %s dialect: engine-level invariants", (name, dialect) => {
  let log: Recorded[];

  beforeEach(async () => {
    log = [];
    const store = new SqlAuthStore(recordingDriver(log), dialect, { now: () => 1_700_000_000_000 });
    await exerciseAll(store);
  });

  it("emits statements at all", () => {
    expect(log.length).toBeGreaterThanOrEqual(11);
  });

  it("🚨 every statement binds EXACTLY as many parameters as it has placeholders", () => {
    for (const { sql, params } of log) {
      const count =
        name === "postgres"
          ? new Set(sql.match(/\$\d+/g) ?? []).size // $1 may legitimately repeat
          : (sql.match(/\?/g) ?? []).length;
      expect({ sql, expected: params.length, found: count }).toEqual({
        sql,
        expected: params.length,
        found: params.length,
      });
    }
  });

  it("🚨 no parameter value is EVER interpolated into the SQL text (injection, at the engine)", () => {
    for (const { sql, params } of log) {
      for (const p of params) {
        if (typeof p !== "string" || p.length < 3) continue;
        // If a value's text appears in the statement, it was concatenated rather than bound —
        // and no amount of escaping makes that safe.
        expect(sql).not.toContain(p);
      }
    }
  });

  it("normalizes the email BEFORE it reaches the driver (never a collation's job)", () => {
    const indexWrite = log.find((r) => /INSERT INTO .*email_index/i.test(r.sql));
    expect(indexWrite).toBeDefined();
    // "  MiXeD@Example.COM " → "mixed@example.com"
    expect(indexWrite!.params).toContain("mixed@example.com");
    expect(indexWrite!.params).not.toContain("  MiXeD@Example.COM ");
  });

  it("every expiry-bearing READ filters on expires_at — no reaper required for correctness", () => {
    const reads = log.filter((r) => /^SELECT|^DELETE FROM \S+ WHERE app_id/i.test(r.sql.trim()));
    const sessionOrChallengeReads = reads.filter((r) => /ttc_sessions|ttc_challenges/i.test(r.sql));
    expect(sessionOrChallengeReads.length).toBeGreaterThan(0);
    for (const r of sessionOrChallengeReads) {
      // deleteSession is an unconditional revoke — it is the only exception.
      if (/DELETE FROM \S*ttc_sessions WHERE app_id = \S+ AND token_hash/i.test(r.sql)) continue;
      expect(r.sql).toMatch(/expires_at\s*>/);
    }
  });

  it("the rate-limit upsert carries the CASE that starts a FRESH window on an expired row", () => {
    const rl = log.find((r) => /INSERT INTO .*rate_limits/i.test(r.sql));
    expect(rl).toBeDefined();
    // Without this CASE, a long-expired counter keeps incrementing, never re-stamps its TTL,
    // and that identifier is rate-limited FOREVER.
    expect(rl!.sql).toMatch(/CASE WHEN .*expires_at <= .* THEN 1 ELSE .*count \+ 1 END/i);
  });

  it("the session's fingerprint is a TYPED COLUMN, never a 'pk|fp' string", () => {
    const put = log.find((r) => /INSERT INTO .*ttc_sessions/i.test(r.sql));
    expect(put).toBeDefined();
    expect(put!.sql).toMatch(/fingerprint/);
    expect(put!.params).toContain(NASTY2); // bound on its own, not concatenated onto the key
    for (const p of put!.params) expect(String(p)).not.toContain("|");
  });
});

describe("ADR-002 — MySQL declares the ONE thing that makes it different", () => {
  it("supportsReturning: false → the engine uses a locking transaction for challenge-consume", () => {
    expect(mysqlDialect().supportsReturning).toBe(false);
    expect(mysqlDialect().forUpdate).toMatch(/FOR UPDATE/i);
    // Postgres and SQLite can do it in one statement.
    expect(postgresDialect().supportsReturning).toBe(true);
    expect(sqliteDialect().supportsReturning).toBe(true);
  });

  it("🚨 MySQL's takeChallenge is still ATOMIC — it locks the row rather than racing", async () => {
    const log: Recorded[] = [];
    const store = new SqlAuthStore(recordingDriver(log), mysqlDialect(), { now: () => 1 });
    await store.takeChallenge("app1", "pk");

    const select = log.find((r) => /^SELECT challenge/i.test(r.sql.trim()));
    expect(select).toBeDefined();
    // Without FOR UPDATE, two concurrent consumers could both read the same challenge before
    // either deleted it — and a single-use login challenge would become REPLAYABLE.
    expect(select!.sql).toMatch(/FOR UPDATE/i);
    expect(select!.sql).toMatch(/expires_at\s*>/); // and expired ⇒ invisible
  });
});
