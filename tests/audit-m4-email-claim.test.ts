// M-4 — registration's email-collision check was check-then-act.
//
// `resolvePublicKeyByEmail` then `persistUser` with nothing in between: two concurrent
// registrations for one address both saw "free", both persisted, and the index write was a
// plain overwrite. The loser's user record SURVIVED but became unreachable by email — they
// could not log in, and their wallets are encrypted under a key only they hold. Silent, and
// both requests returned 201.
//
// 🚨 The audit recorded this as KV-only, on the grounds that SQL's `PRIMARY KEY (email,
// app_id)` made it structurally safe. That was wrong. The unique key stops two ROWS
// existing; the `ON CONFLICT … DO UPDATE SET public_key = ?` upsert let the second
// registration STEAL the first one's row. Both ports had the bug; both are fixed here.
//
// The fix is a CLAIM: hsetnx on KV, read-then-insert inside the transaction on SQL. The
// loser is told (EmailTakenError) rather than silently overwriting, and the handler turns
// that into the same 409 the pre-check produces.
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { KvAuthStore, EmailTakenError } from "../src/storage/store";
import { SqlAuthStore } from "../src/storage/sql/engine";
import { sqliteDialect } from "../src/storage/sql";
import { sqliteDriver } from "../src/storage/sql/drivers";
import { DEFAULT_CONFIG } from "../src/core/config";
import { registerEmail, addressFor } from "./_auth-helpers";
import type { UserData } from "../src/core/types";
import Database from "better-sqlite3";

const APP_KEY = "ab".repeat(32);
const EMAIL = "contested@example.com";

function user(publicKey: string, email = EMAIL): UserData {
  return { appId: "app1", publicKey, email, authMethod: "email", wallets: [], createdAt: 0 };
}

// ---------------------------------------------------------------------------
// The primitive the claim rests on
// ---------------------------------------------------------------------------
describe("hsetnx — the atomic claim", () => {
  it("🚨 only the FIRST writer wins a field", async () => {
    const kv = new MemoryAdapter();
    expect(await kv.hsetnx("h", "f", "first")).toBe(true);
    expect(await kv.hsetnx("h", "f", "second")).toBe(false);
    expect(await kv.hget("h", "f")).toBe("first"); // not overwritten
  });

  it("🚨 concurrent claims resolve to exactly one winner", async () => {
    const kv = new MemoryAdapter();
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => kv.hsetnx("h", "f", `w${i}`)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("distinct fields are independent — one email, two apps", async () => {
    const kv = new MemoryAdapter();
    expect(await kv.hsetnx("email:x", "app1", "PK_A")).toBe(true);
    expect(await kv.hsetnx("email:x", "app2", "PK_B")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// KV store
// ---------------------------------------------------------------------------
describe("KvAuthStore — the email index is claimed, not overwritten", () => {
  const store = () => new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);

  it("🚨 a second identity cannot steal a held address", async () => {
    const s = store();
    await s.putUser(user("PK_A"));
    await expect(s.putUser(user("PK_B"))).rejects.toThrow(EmailTakenError);
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
  });

  it("the owner's own re-write is not a collision", async () => {
    const s = store();
    await s.putUser(user("PK_A"));
    await expect(s.putUser({ ...user("PK_A"), pbkdf2Iterations: 600_000 })).resolves.toBeUndefined();
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
  });

  it("the same address under a DIFFERENT app is untouched", async () => {
    const s = store();
    await s.putUser(user("PK_A"));
    await expect(s.putUser({ ...user("PK_B"), appId: "app2" })).resolves.toBeUndefined();
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
    expect(await s.getPublicKeyByEmail("app2", EMAIL)).toBe("PK_B");
  });

  it("🚨 case permutations contend for the SAME claim", async () => {
    // normalizeEmail runs before the claim, or `Victim@x.com` would quietly hold a second
    // slot for what is the same account.
    const s = store();
    await s.putUser(user("PK_A", "Owner@Example.com"));
    await expect(s.putUser(user("PK_B", "owner@example.com"))).rejects.toThrow(EmailTakenError);
  });
});

// ---------------------------------------------------------------------------
// SQL store — the port the audit wrongly cleared
// ---------------------------------------------------------------------------
describe("SqlAuthStore — the upsert used to let the second registration steal the row", () => {
  function seeded() {
    const db = new Database(":memory:");
    db.exec(sqliteDialect().ddl()); // exec runs the whole multi-statement DDL
    return new SqlAuthStore(sqliteDriver(db), sqliteDialect());
  }

  it("🚨 a second identity cannot steal a held address", async () => {
    const s = seeded();
    await s.putUser(user("PK_A"));
    await expect(s.putUser(user("PK_B"))).rejects.toThrow(EmailTakenError);
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
  });

  it("the owner's own re-write is not a collision", async () => {
    const s = seeded();
    await s.putUser(user("PK_A"));
    await expect(s.putUser({ ...user("PK_A"), pbkdf2Iterations: 600_000 })).resolves.toBeUndefined();
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
  });

  it("two apps still share one address", async () => {
    const s = seeded();
    await s.putUser(user("PK_A"));
    await s.putUser({ ...user("PK_B"), appId: "app2" });
    expect(await s.getPublicKeyByEmail("app1", EMAIL)).toBe("PK_A");
    expect(await s.getPublicKeyByEmail("app2", EMAIL)).toBe("PK_B");
  });
});

// ---------------------------------------------------------------------------
// End-to-end through the route
// ---------------------------------------------------------------------------
describe("POST /register — the race loser gets the same 409 as the pre-check", () => {
  function handlers() {
    return createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        // The global creation ceiling is 2/60s; raise it so it is not what stops the race.
        accountCreationRateLimit: { windowSeconds: 60, maxAttempts: 50 },
      },
      onWarning: () => {},
    });
  }

  it("🚨 concurrent registrations for one email: exactly ONE succeeds", async () => {
    const h = handlers();
    const results = await Promise.all(
      ["r1", "r2", "r3", "r4"].map((label) =>
        registerEmail(h, { publicKey: label, email: "race@test.com", appKey: APP_KEY }),
      ),
    );
    const statuses = results.map((r) => r.status);

    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    expect(statuses.filter((s) => s === 409)).toHaveLength(3);
    // No 500: the loss is an expected outcome, answered cleanly.
    expect(statuses.some((s) => s >= 500)).toBe(false);
  });

  it("🚨 the winner is the account the email actually resolves to", async () => {
    const h = handlers();
    const labels = ["w1", "w2", "w3"];
    const results = await Promise.all(
      labels.map((label) =>
        registerEmail(h, { publicKey: label, email: "winner@test.com", appKey: APP_KEY }),
      ),
    );

    const winnerIdx = results.findIndex((r) => r.status === 201);
    expect(winnerIdx).toBeGreaterThanOrEqual(0);
    const winner = await results[winnerIdx]!.json();

    // Whoever got the 201 must be the one login resolves — not a losing writer.
    expect(winner.publicKey).toBe(addressFor(labels[winnerIdx]!));
  });

  it("sequential re-registration is still a plain 409", async () => {
    const h = handlers();
    expect((await registerEmail(h, { publicKey: "s1", email: "seq@test.com", appKey: APP_KEY })).status).toBe(
      201,
    );
    expect((await registerEmail(h, { publicKey: "s2", email: "seq@test.com", appKey: APP_KEY })).status).toBe(
      409,
    );
  });
});
