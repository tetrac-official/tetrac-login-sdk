// M-6 — the SQL rate limiter failed OPEN on an empty RETURNING.
//
// `Number(rows[0]?.count ?? 1)` read "the upsert returned no row" as "first hit of a new
// window" and allowed the request. That is a security control switching itself off under
// exactly the conditions that broke it — a failing pool, a driver quirk, a permissions
// error on RETURNING. The store contract requires fail-CLOSED: checkRateLimit has no
// try/catch precisely so a store that cannot count 500s rather than granting permission.
//
// M-7 — the Supabase `public`-schema guard was a case-sensitive exact match. Postgres folds
// unquoted identifiers, so `PUBLIC` and `Public` reach the same world-readable schema the
// guard exists to refuse.
import { SqlAuthStore } from "../src/storage/sql/engine";
import { postgresDialect, mysqlDialect } from "../src/storage/sql";
import type { SqlDriver } from "../src/storage/sql/types";

/** A driver whose rate-limit upsert answers with nothing — the M-6 trigger. */
function silentDriver(): SqlDriver {
  const driver: SqlDriver = {
    async query<T>(): Promise<T[]> {
      return [] as T[];
    },
    transaction: (fn) => fn(driver),
  };
  return driver;
}

/** A driver that answers rate-limit reads normally. */
function countingDriver(count: number): SqlDriver {
  const driver: SqlDriver = {
    async query<T>(sql: string): Promise<T[]> {
      if (/count/i.test(sql)) return [{ count }] as unknown as T[];
      return [] as T[];
    },
    transaction: (fn) => fn(driver),
  };
  return driver;
}

describe("M-6 — the rate limiter fails CLOSED, never open", () => {
  it("🚨 postgres: an empty RETURNING throws instead of allowing the request", async () => {
    const store = new SqlAuthStore(silentDriver(), postgresDialect());
    await expect(
      store.hitRateLimit({ endpoint: "login", appId: "app1", identifier: "a@b.com" }, 60, 5),
    ).rejects.toThrow(/refusing to treat an un-countable request as allowed/i);
  });

  it("🚨 mysql: the read-back path throws too (it has no RETURNING)", async () => {
    const store = new SqlAuthStore(silentDriver(), mysqlDialect());
    await expect(
      store.hitRateLimit({ endpoint: "login", appId: "app1", identifier: "a@b.com" }, 60, 5),
    ).rejects.toThrow(/refusing to treat an un-countable request as allowed/i);
  });

  it("a NaN / non-numeric count is also refused, not coerced", async () => {
    const driver: SqlDriver = {
      async query<T>(sql: string): Promise<T[]> {
        if (/count/i.test(sql)) return [{ count: "not-a-number" }] as unknown as T[];
        return [] as T[];
      },
      transaction: (fn) => fn(driver),
    };
    const store = new SqlAuthStore(driver, postgresDialect());
    await expect(store.hitRateLimit({ endpoint: "ip", identifier: "1.2.3.4" }, 60, 5)).rejects.toThrow(
      /un-countable/i,
    );
  });

  it("a real count still works — the guard must not break the happy path", async () => {
    const under = new SqlAuthStore(countingDriver(3), postgresDialect());
    await expect(
      under.hitRateLimit({ endpoint: "login", appId: "app1", identifier: "a@b.com" }, 60, 5),
    ).resolves.toMatchObject({ allowed: true, remaining: 2 });

    const over = new SqlAuthStore(countingDriver(9), postgresDialect());
    await expect(
      over.hitRateLimit({ endpoint: "login", appId: "app1", identifier: "a@b.com" }, 60, 5),
    ).resolves.toMatchObject({ allowed: false, remaining: 0 });
  });

  it("count 0 is a real answer, not a missing one", async () => {
    // Number(0) is falsy — a `?? 1`-style guard is easy to rewrite into a `|| 1` that
    // silently rejects a legitimate zero. It must be accepted.
    const store = new SqlAuthStore(countingDriver(0), postgresDialect());
    await expect(store.hitRateLimit({ endpoint: "ip", identifier: "1.2.3.4" }, 60, 5)).resolves.toMatchObject(
      { allowed: true },
    );
  });
});

describe("M-7 — the Supabase public-schema guard is case-folded", () => {
  const schemaOf = async (schema: string) => {
    const issues = await postgresDialect({ schema }).preflight(silentDriver());
    return issues.filter((i) => i.level === "error").map((i) => i.code);
  };

  it("🚨 refuses PUBLIC / Public / pUbLiC, not just lowercase 'public'", async () => {
    // Postgres lowercases unquoted identifiers, so all of these resolve to the same schema
    // that PostgREST serves to anyone holding the browser-shipped anon key.
    for (const spelling of ["public", "PUBLIC", "Public", "pUbLiC", " public "]) {
      expect(await schemaOf(spelling)).toContain("public_schema");
    }
  });

  it("still allows a genuinely different schema", async () => {
    expect(await schemaOf("tetrac")).not.toContain("public_schema");
    expect(await schemaOf("publicity")).not.toContain("public_schema"); // not a prefix match
  });

  it("the explicit opt-out still works", async () => {
    const issues = await postgresDialect({ schema: "PUBLIC", allowPublicSchema: true }).preflight(
      silentDriver(),
    );
    expect(issues.filter((i) => i.level === "error").map((i) => i.code)).not.toContain("public_schema");
  });
});
