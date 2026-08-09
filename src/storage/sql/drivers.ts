// Thin drivers. Each is ~20 lines and knows nothing about authentication.
//
// Every client is STRUCTURALLY typed (`PgLike`, `MysqlLike`, `SqliteLike`), so the SDK
// never imports `pg` / `mysql2` / `better-sqlite3` and never hard-depends on their types.
// They stay optional peer dependencies: a consumer who doesn't use them pays nothing.
import type { SqlDriver } from "./types.js";

// === Postgres (pg, @vercel/postgres, @neondatabase/serverless) =====================

export interface PgLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  connect?(): Promise<PgClientLike>;
  end?(): Promise<void>;
}
export interface PgClientLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  release(): void;
}

export function pgDriver(pool: PgLike): SqlDriver {
  const driver: SqlDriver = {
    async query<T>(sql: string, params: readonly unknown[]): Promise<T[]> {
      const res = await pool.query(sql, params);
      return res.rows as T[];
    },

    async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
      // A real transaction needs ONE connection — a pool would scatter the statements across
      // several, and the row locks would protect nothing.
      if (!pool.connect) {
        throw new Error(
          "[tetrac] pgDriver: this client cannot check out a connection, so it " +
            "cannot run a real transaction. Pass a pg.Pool (or a Client).",
        );
      }
      const conn = await pool.connect();
      const tx: SqlDriver = {
        async query<U>(sql: string, params: readonly unknown[]): Promise<U[]> {
          const res = await conn.query(sql, params);
          return res.rows as U[];
        },
        transaction: (inner) => inner(tx), // already inside one; don't nest
      };
      try {
        await conn.query("BEGIN");
        const out = await fn(tx);
        await conn.query("COMMIT");
        return out;
      } catch (err) {
        await conn.query("ROLLBACK").catch(() => undefined);
        throw err;
      } finally {
        conn.release();
      }
    },

    close: pool.end ? () => pool.end!() : undefined,
  };
  return driver;
}

// === MySQL / MariaDB (mysql2/promise) =============================================

export interface MysqlLike {
  query(sql: string, values?: readonly unknown[]): Promise<[unknown, unknown]>;
  getConnection?(): Promise<MysqlConnLike>;
  end?(): Promise<void>;
}
export interface MysqlConnLike {
  query(sql: string, values?: readonly unknown[]): Promise<[unknown, unknown]>;
  beginTransaction(): Promise<void>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
  release(): void;
}

const utf8 = new TextDecoder();

/**
 * 🚨 mysql2 returns `VARBINARY` columns as **Buffer**, not string.
 *
 * The MySQL schema uses `VARBINARY` for every key column *on purpose* — it is the only way to
 * get byte-exact comparison, because MySQL's default collation is case-insensitive and even
 * `utf8mb4_bin` is `PAD SPACE` (see dialects/mysql.ts). The cost of that choice is this: the
 * values come back as raw bytes.
 *
 * If we didn't decode them, `getPublicKeyByEmail()` would return a Buffer instead of a string,
 * every `===` against it would be false, and MySQL would fail in a dozen quiet, confusing ways
 * — sessions that never validate, an email index that never resolves. Decoding belongs HERE, in
 * the driver: it is a wire-format concern, not something the engine or a dialect should know.
 *
 * (Every "binary" column holds UTF-8 text. We chose VARBINARY for its comparison semantics, not
 * to store binary data.)
 */
function decode(v: unknown): unknown {
  return v instanceof Uint8Array ? utf8.decode(v) : v;
}

/** mysql2 returns rows for SELECT, and a ResultSetHeader for writes. Normalize both. */
function mysqlRows<T>(result: unknown): T[] {
  if (Array.isArray(result)) {
    return result.map((row) => {
      if (!row || typeof row !== "object") return row;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(row as Record<string, unknown>)) out[k] = decode(v);
      return out;
    }) as T[];
  }
  const header = result as { affectedRows?: number };
  return typeof header?.affectedRows === "number"
    ? ([{ affected: header.affectedRows }] as unknown as T[])
    : [];
}

export function mysqlDriver(pool: MysqlLike): SqlDriver {
  return {
    async query<T>(sql: string, params: readonly unknown[]): Promise<T[]> {
      const [rows] = await pool.query(sql, params);
      return mysqlRows<T>(rows);
    },

    async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
      if (!pool.getConnection) {
        throw new Error(
          "[tetrac] mysqlDriver: this client cannot check out a connection, so it " +
            "cannot run a real transaction — and MySQL NEEDS one (it has no DELETE…RETURNING, " +
            "so atomic challenge-consume depends on SELECT…FOR UPDATE). Pass a mysql2 Pool.",
        );
      }
      const conn = await pool.getConnection();
      const tx: SqlDriver = {
        async query<U>(sql: string, params: readonly unknown[]): Promise<U[]> {
          const [rows] = await conn.query(sql, params);
          return mysqlRows<U>(rows);
        },
        transaction: (inner) => inner(tx),
      };
      try {
        await conn.beginTransaction();
        const out = await fn(tx);
        await conn.commit();
        return out;
      } catch (err) {
        await conn.rollback().catch(() => undefined);
        throw err;
      } finally {
        conn.release();
      }
    },

    close: pool.end ? () => pool.end!() : undefined,
  };
}

// === SQLite (better-sqlite3) ======================================================

export interface SqliteStatementLike {
  all(...params: unknown[]): unknown[];
  run(...params: unknown[]): { changes: number };
}
export interface SqliteLike {
  prepare(sql: string): SqliteStatementLike;
  exec(sql: string): unknown;
  close?(): unknown;
}

export function sqliteDriver(db: SqliteLike): SqlDriver {
  // better-sqlite3 is SYNCHRONOUS, so `db.transaction()` refuses an async callback. We drive
  // BEGIN/COMMIT/ROLLBACK by hand instead.
  //
  // Serializes overlapping transaction() calls — see the comment on transaction() below.
  let tail: Promise<unknown> = Promise.resolve();

  async function query<T>(sql: string, params: readonly unknown[]): Promise<T[]> {
    const stmt = db.prepare(sql);
    // A statement with no result columns (e.g. a plain DELETE) throws on .all() in
    // better-sqlite3, so fall back to .run().
    try {
      return stmt.all(...params) as T[];
    } catch {
      const info = stmt.run(...params);
      return [{ affected: info.changes }] as unknown as T[];
    }
  }

  // The driver handed to a transaction callback. Its `transaction()` JOINS the open
  // transaction instead of starting or queueing one — SQLite has no nested BEGIN.
  //
  // Nesting is distinguished by WHICH OBJECT you hold, not by a mutable depth counter. That
  // is the whole fix: a counter cannot tell "re-entered from inside this transaction" from
  // "a different caller arrived while this one was suspended at an await", and treating the
  // second as the first is what let one caller's writes land inside another's transaction.
  const txDriver: SqlDriver = {
    query,
    transaction: (fn) => fn(txDriver),
    close: undefined,
  };

  const driver: SqlDriver = {
    query,

    async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
      // SERIALIZE, don't collapse.
      //
      // The old guard was `if (depth > 0) return fn(driver)`, justified by "better-sqlite3
      // is synchronous, so nothing can interleave". But `await fn(...)` YIELDS: a second
      // caller could start while the first was suspended, see depth > 0, and run its
      // statements inside the FIRST caller's transaction with no BEGIN of its own. It then
      // reported success while its writes were owned by someone else's transaction — and
      // vanished if that one rolled back. Queueing gives every caller its own real
      // BEGIN/COMMIT, which is what takeChallenge's atomicity depends on.
      const run = async (): Promise<T> => {
        // BEGIN throwing (locked database) must leave NO residue. It previously sat after a
        // `depth++` that was outside the try, so one failure pinned depth above zero for the
        // life of the process and every later transaction silently ran with none at all.
        db.exec("BEGIN IMMEDIATE"); // IMMEDIATE: take the write lock up front, no upgrade deadlock
        try {
          const out = await fn(txDriver);
          db.exec("COMMIT");
          return out;
        } catch (err) {
          try {
            db.exec("ROLLBACK");
          } catch {
            /* already rolled back */
          }
          throw err;
        }
      };

      // Chain onto whatever is in flight. Failures must not break the chain, so the tail
      // swallows the previous outcome — each caller still receives its own.
      const queued = tail.then(run, run);
      tail = queued.then(
        () => undefined,
        () => undefined,
      );
      return queued;
    },

    close: db.close ? async () => void db.close!() : undefined,
  };
  return driver;
}
