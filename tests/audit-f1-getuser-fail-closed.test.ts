// Audit 2026-08-08 F-1 — a backend failure must never read as "account absent".
//
// `getUser` used to wrap the profile JSON.parse AND the wallets query in one catch that
// returned null. `null` from getUser is a promise that the backend answered and the
// record is ABSENT, and connect-wallet acts on it: the creation branch persists a
// freshly-generated bundle, upserting over every stored wallet slot. `encryptedSecret`
// is the only copy of that private key — no escrow, no re-derivation — so one dropped
// connection mid-request became silent, permanent key loss, with both requests 2xx.
//
// getUser now fails closed: a failing wallets query and an unparseable row both THROW.
// The request 500s and the record survives.
import Database from "better-sqlite3";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { SqlAuthStore } from "../src/storage/sql/engine";
import { sqliteDriver } from "../src/storage/sql/drivers";
import { sqliteDialect } from "../src/storage/sql/dialects/sqlite";
import type { SqlDriver } from "../src/storage/sql/types";
import { KvAuthStore } from "../src/storage/store";
import { MemoryAdapter } from "../src/storage/memory";
import { DEFAULT_CONFIG } from "../src/core/config";
import { createAuthHandlers } from "../src/server/routes";
import { walletLoginMessage } from "../src/core/index";
import { jreq } from "./_auth-helpers";

const ORIGIN = "https://test.example";
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** A SQLite store whose driver can be told to fail ONLY the wallets-table SELECT —
 *  the shape of a dropped connection / statement timeout on the second round trip. */
function flakyStore() {
  const db = new Database(":memory:");
  db.exec(sqliteDialect().ddl());
  const inner = sqliteDriver(db as never);
  const state = { failWalletsSelect: false };
  const driver: SqlDriver = {
    query<T>(sql: string, params: readonly unknown[]) {
      if (state.failWalletsSelect && /^\s*SELECT/i.test(sql) && /FROM ttc_user_wallets/i.test(sql)) {
        return Promise.reject(new Error("connection reset by peer"));
      }
      return inner.query<T>(sql, params);
    },
    transaction: (fn) => inner.transaction(fn),
  };
  return { db, state, store: new SqlAuthStore(driver, sqliteDialect()) };
}

async function connect(
  h: ReturnType<typeof createAuthHandlers>,
  kp: Keypair,
  encryptedSecret: string,
): Promise<Response> {
  const publicKey = kp.publicKey.toBase58();
  const ch = (await (await h.challenge(jreq({ publicKey }))).json()) as { challenge: string };
  const msg = new TextEncoder().encode(
    walletLoginMessage({ challenge: ch.challenge, origin: ORIGIN, address: publicKey }),
  );
  return h.connectWallet(
    jreq({
      publicKey,
      signature: toHex(nacl.sign.detached(msg, kp.secretKey)),
      challenge: ch.challenge,
      wallets: [{ chain: "solana", role: "funds", publicKey: "addr1", encryptedSecret }],
    }),
  );
}

describe("F-1 — SqlAuthStore.getUser fails closed", () => {
  it("🚨 a failing wallets query PROPAGATES — it does not return null", async () => {
    const { state, store } = flakyStore();
    await store.putUser({
      appId: "ttc",
      publicKey: "pk1",
      authMethod: "wallet",
      wallets: [{ chain: "solana", role: "funds", publicKey: "addr1", encryptedSecret: "iv:ORIGINAL" }],
      createdAt: 1,
    });

    state.failWalletsSelect = true;
    await expect(store.getUser("ttc", "pk1")).rejects.toThrow(/connection reset/);

    // The backend recovered — the record is intact, ciphertext untouched.
    state.failWalletsSelect = false;
    const user = await store.getUser("ttc", "pk1");
    expect(user?.wallets?.[0]?.encryptedSecret).toBe("iv:ORIGINAL");
  });

  it("an unparseable profile row throws — a row that EXISTS is never reported absent", async () => {
    const { db, store } = flakyStore();
    db.prepare("INSERT INTO ttc_users (app_id, public_key, data, auth_token_hash) VALUES (?, ?, ?, ?)").run(
      "ttc",
      "pk-corrupt",
      "not-json{",
      null,
    );

    await expect(store.getUser("ttc", "pk-corrupt")).rejects.toThrow();
  });
});

describe("F-1 — KvAuthStore.getUser fails closed", () => {
  it("an unparseable stored profile throws — never null", async () => {
    const storage = new MemoryAdapter();
    const store = new KvAuthStore(storage, DEFAULT_CONFIG.keyPrefixes);
    await storage.hset("pubKey:ttc:pk-corrupt", "p", "not-json{");

    await expect(store.getUser("ttc", "pk-corrupt")).rejects.toThrow();
  });
});

describe("F-1 — end-to-end: connect-wallet during a backend failure cannot destroy stored wallet keys", () => {
  it("🚨 the failing request throws (500), and the original ciphertext survives", async () => {
    const { db, state, store } = flakyStore();
    const h = createAuthHandlers({ store, config: { origin: ORIGIN } });
    const kp = Keypair.generate();

    expect((await connect(h, kp, "iv:ORIGINAL")).status).toBe(201);

    // The wallets SELECT drops mid-request. getUser used to answer null here, the handler
    // took the creation branch, and this connect returned 201 with a REGENERATED bundle.
    state.failWalletsSelect = true;
    await expect(connect(h, kp, "iv:REGENERATED")).rejects.toThrow(/connection reset/);

    const row = db
      .prepare("SELECT data FROM ttc_user_wallets WHERE app_id = ? AND public_key = ?")
      .all("ttc", kp.publicKey.toBase58()) as Array<{ data: string }>;
    expect(row).toHaveLength(1);
    expect(JSON.parse(row[0]!.data).encryptedSecret).toBe("iv:ORIGINAL");

    // Backend recovers: the SAME wallet logs in (200, not 201) and keeps its keys.
    state.failWalletsSelect = false;
    const again = await connect(h, kp, "iv:REGENERATED-2");
    expect(again.status).toBe(200);
    const body = (await again.json()) as { user: { wallets: Array<{ encryptedSecret: string }> } };
    expect(body.user.wallets[0]!.encryptedSecret).toBe("iv:ORIGINAL");
  });
});
