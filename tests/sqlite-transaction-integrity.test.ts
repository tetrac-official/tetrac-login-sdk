// M-5 — the SQLite driver's transaction() had two defects, both of which silently void the
// atomicity that takeChallenge (the entire challenge-replay defence) depends on.
//
//  (a) COLLAPSE. `if (depth > 0) return fn(driver)` assumed nothing could interleave because
//      better-sqlite3 is synchronous. But `await fn(driver)` YIELDS: a second caller could
//      start while the first was suspended, see depth > 0, and run its statements inside the
//      FIRST caller's transaction with no BEGIN of its own. It then reported success while
//      its writes belonged to someone else's transaction — and vanished if that one rolled
//      back.
//
//  (b) PERMANENT CORRUPTION. `depth++` sat before `db.exec("BEGIN IMMEDIATE")` and outside
//      the try/finally. A throwing BEGIN (locked database) left depth pinned above zero for
//      the life of the process, after which EVERY subsequent transaction took the collapse
//      path and ran with no transaction at all.
import { sqliteDriver } from "../src/storage/sql/drivers";
import type { SqliteLike } from "../src/storage/sql/drivers";

/** A minimal better-sqlite3 stand-in that records the statements it is told to run. */
function fakeDb(opts: { failBeginOnce?: boolean } = {}) {
  const execLog: string[] = [];
  let beginFailuresLeft = opts.failBeginOnce ? 1 : 0;

  const db: SqliteLike = {
    prepare(_sql: string) {
      return {
        all: () => [],
        run: () => ({ changes: 0 }),
      } as unknown as ReturnType<SqliteLike["prepare"]>;
    },
    exec(sql: string) {
      if (sql.startsWith("BEGIN") && beginFailuresLeft > 0) {
        beginFailuresLeft--;
        execLog.push("BEGIN(threw)");
        throw new Error("database is locked");
      }
      execLog.push(sql);
    },
  } as unknown as SqliteLike;

  return { db, execLog };
}

describe("M-5(b) — a failed BEGIN must not permanently disable transactions", () => {
  it("🚨 the next transaction still gets its own BEGIN/COMMIT", async () => {
    const { db, execLog } = fakeDb({ failBeginOnce: true });
    const driver = sqliteDriver(db);

    // First call: BEGIN throws. The depth counter must be restored on the way out.
    await expect(driver.transaction(async () => "never")).rejects.toThrow(/locked/i);

    // Second call must behave like a first-class transaction, not silently run bare.
    const out = await driver.transaction(async () => "ok");
    expect(out).toBe("ok");

    expect(execLog).toEqual(["BEGIN(threw)", "BEGIN IMMEDIATE", "COMMIT"]);
  });

  it("🚨 repeated BEGIN failures do not accumulate depth", async () => {
    const { db } = fakeDb();
    const driver = sqliteDriver(db);
    let fail = true;
    const flaky = {
      ...db,
      exec(sql: string) {
        if (sql.startsWith("BEGIN") && fail) throw new Error("database is locked");
        return (db as unknown as { exec(s: string): void }).exec(sql);
      },
    } as unknown as SqliteLike;
    const d2 = sqliteDriver(flaky);

    for (let i = 0; i < 5; i++) {
      await expect(d2.transaction(async () => "x")).rejects.toThrow(/locked/i);
    }
    fail = false;
    await expect(d2.transaction(async () => "recovered")).resolves.toBe("recovered");
    void driver;
  });
});

describe("M-5(a) — overlapping transactions are serialized, not collapsed", () => {
  it("🚨 each concurrent caller gets its OWN BEGIN and COMMIT", async () => {
    const { db, execLog } = fakeDb();
    const driver = sqliteDriver(db);

    // Both callers await inside the callback, which is exactly what made the old
    // "synchronous, so nothing can interleave" reasoning wrong.
    const a = driver.transaction(async () => {
      await Promise.resolve();
      db.exec("-- A work");
      await Promise.resolve();
      return "a";
    });
    const b = driver.transaction(async () => {
      await Promise.resolve();
      db.exec("-- B work");
      return "b";
    });

    expect(await Promise.all([a, b])).toEqual(["a", "b"]);

    // Two complete, non-overlapping transactions. Collapsed, B's work landed between A's
    // BEGIN and COMMIT with no BEGIN of its own.
    expect(execLog).toEqual([
      "BEGIN IMMEDIATE",
      "-- A work",
      "COMMIT",
      "BEGIN IMMEDIATE",
      "-- B work",
      "COMMIT",
    ]);
  });

  it("🚨 a failing transaction does not poison the ones queued behind it", async () => {
    const { db, execLog } = fakeDb();
    const driver = sqliteDriver(db);

    const bad = driver.transaction(async () => {
      await Promise.resolve();
      throw new Error("boom");
    });
    const good = driver.transaction(async () => {
      await Promise.resolve();
      db.exec("-- survivor");
      return "ok";
    });

    await expect(bad).rejects.toThrow(/boom/);
    await expect(good).resolves.toBe("ok");

    expect(execLog).toEqual(["BEGIN IMMEDIATE", "ROLLBACK", "BEGIN IMMEDIATE", "-- survivor", "COMMIT"]);
  });

  it("a genuinely nested call still reuses the open transaction", async () => {
    // SQLite has no nested BEGIN. Re-entrancy from INSIDE a transaction must still join it —
    // the fix serializes separate callers, it does not forbid nesting.
    const { db, execLog } = fakeDb();
    const driver = sqliteDriver(db);

    await driver.transaction(async (tx) => {
      db.exec("-- outer");
      await tx.transaction(async () => {
        db.exec("-- inner");
        return null;
      });
      return null;
    });

    expect(execLog).toEqual(["BEGIN IMMEDIATE", "-- outer", "-- inner", "COMMIT"]);
  });
});
