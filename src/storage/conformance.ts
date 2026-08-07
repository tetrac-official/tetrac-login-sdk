// The AuthStore conformance suite — the acceptance bar for ANY storage backend.
//
// Framework-agnostic ON PURPOSE: it returns cases rather than calling describe/it, so a
// third-party backend author can run it under Jest, Vitest, or node:test without taking
// a dependency on ours:
//
//   import { authStoreConformanceCases } from "@tetrac/login-sdk/storage/conformance";
//   for (const c of authStoreConformanceCases(() => new MyStore(client))) {
//     it(c.name, () => c.run());
//   }
//
// A KV backend runs the SAME suite through the wrapper — there is exactly one bar:
//
//   authStoreConformanceCases(() => new KvAuthStore(new MyAdapter(client)))
//
// Every case here corresponds to a way a plausible-looking backend is catastrophically
// wrong: it passes a smoke test, and then days later permanently locks users out,
// accepts expired sessions, replays a challenge, or merges two accounts. Run it against
// a REAL engine in Docker, not a mock — atomicity, collation and expiry are properties
// of the engine, and a mock only asserts you mocked it the way you imagined.
import type { AuthStore } from "./store.js";
import { WALLET_SLOTS, type UserData, type EncryptedWallet } from "../core/types.js";

export interface ConformanceCase {
  name: string;
  /** Throws on failure. */
  run(): Promise<void>;
}

export interface ConformanceOptions {
  /**
   * Advance the store's notion of time by `ms`. Supply this when the backend accepts an
   * injectable clock (MemoryAdapter does) — it makes the expiry cases instant. When
   * omitted, the suite really sleeps, which is what you want against a real engine.
   */
  advance?: (ms: number) => Promise<void> | void;
  /** Set true if the backend implements the optional `sweepExpired`. */
  supportsSweep?: boolean;
}

// --- tiny assertion kit (no test-framework dependency) ---------------------------

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`conformance: ${msg}`);
}

function assertEqual<T>(actual: T, expected: T, msg: string): void {
  if (actual !== expected) {
    throw new Error(
      `conformance: ${msg} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

// --- fixtures ---------------------------------------------------------------------

const PK_A = "AaBbCcDdEeFfGgHhJjKkLmNnPpQqRrSsTtUuVvWwXxYy";
const PK_B = "ZzYyXxWwVvUuTtSsRrQqPpNnMmLlKkJjHhGgFfEeDdCc";

function makeUser(over: Partial<UserData> = {}): UserData {
  return {
    appId: "app1",
    publicKey: PK_A,
    authMethod: "email",
    wallets: [],
    createdAt: 1_700_000_000_000,
    ...over,
  } as UserData;
}

/**
 * The LARGEST UserData the server will ever persist: all four (chain, role) slots filled,
 * each carrying a max-length encryptedSecret (8192 chars) — roughly 33 KB.
 *
 * The record is slot-bounded, not count-bounded: `validateWallets` rejects a fifth entry
 * and any duplicate slot, and import REPLACES a slot rather than appending. So this is a
 * real worst case a backend must round-trip byte-identically, not an arbitrary number.
 */
function makeMaxWalletUser(): UserData {
  const wallets: EncryptedWallet[] = WALLET_SLOTS.map((slot, i) => ({
    ...slot,
    publicKey: `${PK_A}${i}`,
    encryptedSecret: `${"a1b2c3d4".repeat(1024)}:${String(i).padStart(4, "0")}`,
  }));
  return makeUser({ wallets, email: "max@example.com" });
}

export function authStoreConformanceCases(
  makeStore: () => AuthStore | Promise<AuthStore>,
  opts: ConformanceOptions = {},
): ConformanceCase[] {
  const advance = opts.advance ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms + 100)));

  const cases: ConformanceCase[] = [];
  const add = (name: string, run: (store: AuthStore) => Promise<void>): void => {
    cases.push({
      name,
      run: async () => {
        const store = await makeStore();
        try {
          await run(store);
        } finally {
          await store.close?.();
        }
      },
    });
  };

  // === RATE LIMITING ==============================================================
  // The nastiest bug class in the storage layer. A backend whose counter outlives its
  // window leaves the identifier — an IP, an email, a public key — rate-limited FOREVER.

  add(
    "🚨 rate limit: after the window elapses, a previously-limited identifier is allowed again",
    async (store) => {
      const bucket = { endpoint: "login", appId: "app1", identifier: "victim@example.com" };
      // Burn through the limit.
      for (let i = 0; i < 3; i++) await store.hitRateLimit(bucket, 1, 3);
      const blocked = await store.hitRateLimit(bucket, 1, 3);
      assertEqual(blocked.allowed, false, "4th hit of a max-3 window must be denied");

      // Let the window pass. NOTHING else happens — no sweep, no reaper.
      await advance(1000);

      const afterWindow = await store.hitRateLimit(bucket, 1, 3);
      assert(
        afterWindow.allowed,
        "PERMANENT LOCKOUT: the identifier is still limited after its window elapsed. " +
          "The counter survived its own expiry — this is a self-inflicted, permanent denial " +
          "of service for that IP/email/public key, and it only appears under sustained traffic.",
      );
      assertEqual(afterWindow.remaining, 2, "a fresh window must start at 1 hit (of 3)");
    },
  );

  add("rate limit: a live window is not silently extended by further hits", async (store) => {
    const bucket = { endpoint: "login", appId: "app1", identifier: "drift@example.com" };
    await store.hitRateLimit(bucket, 2, 10); // opens the window
    await advance(1000); // half of it elapses
    await store.hitRateLimit(bucket, 2, 10); // a hit mid-window must NOT reset the clock
    await advance(1500); // total > 2s: the ORIGINAL window has now expired

    const r = await store.hitRateLimit(bucket, 2, 10);
    assertEqual(
      r.remaining,
      9,
      "the window must expire on its original schedule; a mid-window hit that refreshes " +
        "the TTL turns a fixed window into a sliding one that never drains",
    );
  });

  add("rate limit: buckets are isolated by identifier, endpoint, and app", async (store) => {
    const base = { endpoint: "login", appId: "app1", identifier: "alice@example.com" };
    for (let i = 0; i < 5; i++) await store.hitRateLimit(base, 60, 5);
    assertEqual((await store.hitRateLimit(base, 60, 5)).allowed, false, "alice is limited");

    // A different identifier, endpoint, or tenant must have its own budget — otherwise
    // one abuser locks out every user, or exhausts the bucket a victim needs elsewhere.
    assert(
      (await store.hitRateLimit({ ...base, identifier: "bob@example.com" }, 60, 5)).allowed,
      "a different identifier must not inherit alice's counter",
    );
    assert(
      (await store.hitRateLimit({ ...base, endpoint: "challenge" }, 60, 5)).allowed,
      "a different endpoint must not inherit alice's counter (a failed-login flood must " +
        "not lock the victim out of /challenge)",
    );
    assert(
      (await store.hitRateLimit({ ...base, appId: "app2" }, 60, 5)).allowed,
      "a different tenant must not inherit alice's counter",
    );
  });

  // === CHALLENGES =================================================================

  add("🚨 challenge: N concurrent takeChallenge — exactly ONE caller wins", async (store) => {
    const c = "a".repeat(64);
    await store.putChallenge("app1", PK_A, c, 300);

    const results = await Promise.all(Array.from({ length: 8 }, () => store.takeChallenge("app1", PK_A, c)));
    assertEqual(
      results.filter(Boolean).length,
      1,
      "CHALLENGE REPLAY: more than one caller consumed the same single-use challenge. " +
        "takeChallenge must be an ATOMIC get-and-delete — it is the sole mechanism closing " +
        "the replay race.",
    );
  });

  add("challenge: a consumed challenge is gone", async (store) => {
    const c = "b".repeat(64);
    await store.putChallenge("app1", PK_A, c, 300);
    assertEqual(await store.takeChallenge("app1", PK_A, c), true, "first take consumes it");
    assertEqual(await store.takeChallenge("app1", PK_A, c), false, "second take must fail");
  });

  add("🚨 challenge: issuing a NEW challenge does not invalidate one already in flight", async (store) => {
    // A single slot per identity was a targeted denial of login: /challenge is
    // unauthenticated and accepts any public key, so one request from anywhere
    // overwrote whatever the account's owner was in the middle of signing — a ~7s
    // window at securityLevel 2, repeatable indefinitely.
    const inFlight = "c".repeat(64);
    const attacker = "d".repeat(64);
    await store.putChallenge("app1", PK_A, inFlight, 300);
    await store.putChallenge("app1", PK_A, attacker, 300);

    assertEqual(
      await store.takeChallenge("app1", PK_A, inFlight),
      true,
      "TARGETED LOCKOUT: issuing a second challenge destroyed the first. Challenges must " +
        "ACCUMULATE per identity — each expiring on its own — so that anyone able to name " +
        "an account cannot invalidate its owner's in-flight login.",
    );
    // …and the two are independent: burning one leaves the other usable.
    assertEqual(await store.takeChallenge("app1", PK_A, attacker), true, "the other survives");
  });

  add("challenge: consuming one value does not consume a different one", async (store) => {
    const a = "e".repeat(64);
    const b = "f".repeat(64);
    await store.putChallenge("app1", PK_A, a, 300);
    await store.putChallenge("app1", PK_A, b, 300);
    assertEqual(await store.takeChallenge("app1", PK_A, a), true, "a is consumed");
    assertEqual(await store.takeChallenge("app1", PK_A, a), false, "a is now gone");
    assertEqual(await store.takeChallenge("app1", PK_A, b), true, "b was untouched");
  });

  add("🚨 challenge: an expired challenge is invisible — with NO sweep having run", async (store) => {
    const c = "1".repeat(64);
    await store.putChallenge("app1", PK_A, c, 1);
    await advance(1000);
    assertEqual(
      await store.takeChallenge("app1", PK_A, c),
      false,
      "expiry MUST be enforced on the READ path. A TTL index / cron / reaper is space " +
        "reclamation only — Mongo sweeps ~60s late, DynamoDB up to days — and relying on " +
        "it means accepting expired challenges.",
    );
  });

  add("challenge: an absent challenge returns false (never throws)", async (store) => {
    assertEqual(await store.takeChallenge("app1", PK_B, "9".repeat(64)), false, "absent is false");
  });

  // === SESSIONS ===================================================================

  add("session: put → get round-trips the owner and the fingerprint", async (store) => {
    await store.putSession("app1", "hash-1", { publicKey: PK_A }, 300);
    const s = await store.getSession("app1", "hash-1");
    assertEqual(s?.publicKey, PK_A, "session owner round-trips");
    assertEqual(s?.fingerprint, undefined, "an unbound session has no fingerprint");

    await store.putSession("app1", "hash-2", { publicKey: PK_A, fingerprint: "fp-abc" }, 300);
    const bound = await store.getSession("app1", "hash-2");
    assertEqual(bound?.publicKey, PK_A, "bound session owner round-trips");
    assertEqual(bound?.fingerprint, "fp-abc", "bound session fingerprint round-trips");
  });

  add("🚨 session: an expired session is invisible — with NO sweep having run", async (store) => {
    await store.putSession("app1", "hash-exp", { publicKey: PK_A }, 1);
    await advance(1000);
    assertEqual(
      await store.getSession("app1", "hash-exp"),
      null,
      "EXPIRED SESSION ACCEPTED: verifySession accepts any non-null value getSession " +
        "returns, so a backend that leaves expired sessions readable silently extends the " +
        "life of every leaked bearer token.",
    );
  });

  add("session: deleteSession revokes immediately", async (store) => {
    await store.putSession("app1", "hash-3", { publicKey: PK_A }, 300);
    await store.deleteSession("app1", "hash-3");
    assertEqual(await store.getSession("app1", "hash-3"), null, "revoked session must be gone");
  });

  add("session: sessions are isolated per tenant", async (store) => {
    await store.putSession("app1", "shared-hash", { publicKey: PK_A }, 300);
    assertEqual(
      await store.getSession("app2", "shared-hash"),
      null,
      "a session minted by one app must never be honored by another",
    );
  });

  // === USERS & THE EMAIL INDEX ====================================================

  add("user: put → get round-trips", async (store) => {
    const u = makeUser({ email: "a@example.com", authPublicKey: "ab".repeat(32) });
    await store.putUser(u);
    const got = await store.getUser("app1", PK_A);
    assertEqual(got?.publicKey, PK_A, "publicKey round-trips");
    assertEqual(got?.email, "a@example.com", "email round-trips");
    assertEqual(got?.authPublicKey, "ab".repeat(32), "authPublicKey round-trips");
  });

  add("user: absent user is null (never throws)", async (store) => {
    assertEqual(await store.getUser("app1", PK_B), null, "absent user is null");
  });

  add("🚨 user: a max-size UserData round-trips BYTE-IDENTICAL (no silent truncation)", async (store) => {
    const u = makeMaxWalletUser();
    await store.putUser(u);
    const got = await store.getUser("app1", PK_A);
    assert(got, "the max-size record must be readable");
    assertEqual(got.wallets.length, WALLET_SLOTS.length, "every wallet slot must survive");
    assertEqual(
      JSON.stringify(got.wallets),
      JSON.stringify(u.wallets),
      "SILENT TRUNCATION ⇒ PERMANENT WALLET LOCKOUT: a value column too small (MySQL TEXT " +
        "in non-strict mode truncates rather than erroring) yields invalid JSON, so the " +
        "record reads back as null and the user loses access to EVERY wallet in it, with " +
        "nothing anywhere pointing at the database.",
    );
  });

  add("email index: resolves to the publicKey for that app", async (store) => {
    await store.putUser(makeUser({ email: "idx@example.com" }));
    assertEqual(
      await store.getPublicKeyByEmail("app1", "idx@example.com"),
      PK_A,
      "the email index must resolve to the account's publicKey",
    );
    assertEqual(
      await store.getPublicKeyByEmail("app2", "idx@example.com"),
      null,
      "the same email under a DIFFERENT app must not resolve — the index is per-tenant",
    );
  });

  add("email index: matching is case-insensitive and trimmed", async (store) => {
    await store.putUser(makeUser({ email: "MixedCase@Example.COM" }));
    assertEqual(
      await store.getPublicKeyByEmail("app1", "  mixedcase@example.com  "),
      PK_A,
      "email lookup must normalize (lowercase + trim) — use the exported normalizeEmail(). " +
        "Do NOT delegate this to the column's collation: on MySQL that would ALSO case-fold " +
        "the appId and the base58 publicKey, merging distinct tenants and distinct accounts.",
    );
  });

  add(
    "🚨 user record: a wallet-slot write and a session-pointer write do NOT clobber each other",
    async (store) => {
      // The user record must NOT be a single blob that every write rewrites wholesale.
      // When it was, an import overlapping a login resolved last-write-wins and silently
      // destroyed one of them — and `encryptedSecret` is the ONLY copy of that private
      // key, so the funds at that address became permanently unreachable.
      const u = makeUser({ publicKey: PK_A, email: "slots@example.com", wallets: [] });
      await store.putUser(u);

      const wallet = {
        chain: "evm" as const,
        role: "funds" as const,
        publicKey: "0xabc",
        encryptedSecret: "IMPORTED",
      };
      await Promise.all([
        store.putWalletSlot(u.appId, PK_A, wallet),
        store.setSessionPointer(u.appId, PK_A, "d".repeat(64)),
      ]);

      const got = await store.getUser(u.appId, PK_A);
      assertEqual(
        got?.wallets.find((w) => w.chain === "evm" && w.role === "funds")?.encryptedSecret,
        "IMPORTED",
        "LOST WRITE: the session-pointer write destroyed a wallet. These are different " +
          "fields of the record and must be writable independently — a whole-record " +
          "read-modify-write here loses an unrecoverable private key.",
      );
      assertEqual(got?.authTokenHash, "d".repeat(64), "the session pointer was lost");
    },
  );

  add("🚨 user record: writing one wallet slot leaves the other slots untouched", async (store) => {
    const solana = {
      chain: "solana" as const,
      role: "funds" as const,
      publicKey: PK_A,
      encryptedSecret: "KEEP-ME",
    };
    const u = makeUser({ publicKey: PK_B, email: "twoslots@example.com", wallets: [solana] });
    await store.putUser(u);

    await store.putWalletSlot(u.appId, PK_B, {
      chain: "evm",
      role: "signing",
      publicKey: "0xdef",
      encryptedSecret: "NEW",
    });

    const got = await store.getUser(u.appId, PK_B);
    assertEqual(got?.wallets.length, 2, "writing one slot must not drop another");
    assertEqual(
      got?.wallets.find((w) => w.chain === "solana")?.encryptedSecret,
      "KEEP-ME",
      "LOST WRITE: an unrelated slot was destroyed by a slot-scoped write",
    );
  });

  add("🚨 email index: the SAME email under ONE app is CLAIMED, never stolen", async (store) => {
    // The handler checks "is this email taken?" before writing, but check-then-act is not
    // atomic — two concurrent registrations both see "free". An upsert lets the second
    // STEAL the row: the first account still exists but is no longer reachable by email,
    // so its owner cannot log in, and only they hold the key to their wallets.
    //
    // The store is the only layer that can settle this. It must claim, and the loser must
    // be told, not silently overwritten.
    const first = makeUser({ appId: "app1", publicKey: PK_A, email: "contested@example.com" });
    await store.putUser(first);

    const second = makeUser({ appId: "app1", publicKey: PK_B, email: "contested@example.com" });
    let rejected = false;
    try {
      await store.putUser(second);
    } catch {
      rejected = true;
    }

    assert(
      rejected,
      "SILENT STEAL: putUser accepted a second identity for an email another key already " +
        "holds. It must throw (EmailTakenError) so the caller can answer 409.",
    );
    assertEqual(
      await store.getPublicKeyByEmail("app1", "contested@example.com"),
      PK_A,
      "the ORIGINAL owner must still hold the address after a losing claim",
    );
  });

  add("email index: re-writing a user's OWN record is not a collision", async (store) => {
    // putUser serves updates too. Claiming must be idempotent for the current holder, or
    // every profile write after registration would fail.
    const u = makeUser({ appId: "app1", publicKey: PK_A, email: "owner@example.com" });
    await store.putUser(u);
    await store.putUser({ ...u, pbkdf2Iterations: 600_000 });

    assertEqual(
      await store.getPublicKeyByEmail("app1", "owner@example.com"),
      PK_A,
      "a user's own re-write must keep its index entry",
    );
  });

  add(
    "🚨 email index: concurrent putUser for one email under two apps — NEITHER write is lost",
    async (store) => {
      const a = makeUser({ appId: "app1", publicKey: PK_A, email: "shared@example.com" });
      const b = makeUser({ appId: "app2", publicKey: PK_B, email: "shared@example.com" });

      await Promise.all([store.putUser(a), store.putUser(b)]);

      assertEqual(
        await store.getPublicKeyByEmail("app1", "shared@example.com"),
        PK_A,
        "app1's index entry was lost",
      );
      assertEqual(
        await store.getPublicKeyByEmail("app2", "shared@example.com"),
        PK_B,
        "LOST WRITE: app2's index entry was clobbered. The email index must be written " +
          "PER-FIELD/PER-ROW — a backend that reads the whole index, merges in JS, and writes " +
          "it back reintroduces exactly the race this design eliminates, and a registration " +
          "silently vanishes.",
      );
    },
  );

  // === TENANT & ACCOUNT ISOLATION =================================================

  add("🚨 isolation: tenants differing only in CASE are distinct", async (store) => {
    await store.putUser(makeUser({ appId: "Acme", publicKey: PK_A }));
    await store.putUser(makeUser({ appId: "acme", publicKey: PK_B }));

    assertEqual((await store.getUser("Acme", PK_A))?.publicKey, PK_A, "Acme's record");
    assertEqual(
      await store.getUser("Acme", PK_B),
      null,
      "CROSS-TENANT COLLISION: `Acme` and `acme` resolved to the same namespace. A " +
        "case-insensitive collation (MySQL's DEFAULT) merges distinct tenants — and an " +
        "allowedAppIds allowlist does not save you, since both spellings can be on it.",
    );
  });

  add("🚨 isolation: public keys differing only in CASE are distinct accounts", async (store) => {
    // base58 is case-SENSITIVE: these are two different Solana addresses.
    const upper = "AaBbCc";
    const lower = "aabbcc";
    await store.putUser(makeUser({ publicKey: upper, email: undefined }));
    await store.putUser(makeUser({ publicKey: lower, email: undefined }));

    const u = await store.getUser("app1", upper);
    assertEqual(
      u?.publicKey,
      upper,
      "CROSS-ACCOUNT COLLISION: two distinct base58 public keys differing only in case " +
        "mapped to the same row — one user's record overwrote another's. Key columns must " +
        "use a BINARY, NON-PADDING collation (VARBINARY, or utf8mb4_0900_bin — never " +
        "utf8mb4_bin, which is PAD SPACE).",
    );
  });

  add(
    "🚨 isolation: a dotted appId (`myapp.example`) does not collide with its prefix (`myapp`)",
    async (store) => {
      // The appId regex PERMITS '.', and a domain is the SDK's own RECOMMENDED format —
      // so this is the normal configuration, not an exotic one.
      await store.putUser(makeUser({ appId: "myapp", publicKey: PK_A, email: "d@example.com" }));
      await store.putUser(makeUser({ appId: "myapp.example", publicKey: PK_B, email: "d@example.com" }));

      assertEqual(
        await store.getPublicKeyByEmail("myapp", "d@example.com"),
        PK_A,
        "`myapp` lost its index entry to `myapp.example`",
      );
      assertEqual(
        await store.getPublicKeyByEmail("myapp.example", "d@example.com"),
        PK_B,
        "CROSS-TENANT DATA LOSS: the tenants collided. On MongoDB the natural " +
          '`$set: {["fields." + appId]: v}` reads the dot as NESTING, so `myapp.example` ' +
          "becomes a child of `myapp` — one silently destroys the other, or the write " +
          "hard-errors and registration fails. Give the index its own collection/table keyed " +
          "(key, field), passing both as scalar VALUES.",
      );
    },
  );

  // === INJECTION ==================================================================

  add("🚨 injection: SQL/NoSQL-shaped values round-trip as inert data", async (store) => {
    const nasty = [
      "' OR 1=1 --",
      '{"$gt":""}',
      '{"$ne":null}',
      "'; DROP TABLE ttc_kv; --",
      "$where",
      "a.b.c",
    ];

    for (const [i, payload] of nasty.entries()) {
      // As a challenge value, a session owner, and a rate-limit identifier: the backend
      // must treat every one of these as OPAQUE DATA and never as syntax.
      // The challenge is now part of the lookup key, so an injection-shaped VALUE must
      // still address exactly its own entry and nothing else.
      await store.putChallenge("app1", `pk-${i}`, payload, 300);
      assertEqual(
        await store.takeChallenge("app1", `pk-${i}`, payload),
        true,
        `injection-shaped challenge value must address exactly its own entry: ${payload}`,
      );

      await store.putSession("app1", `h-${i}`, { publicKey: payload }, 300);
      assertEqual(
        (await store.getSession("app1", `h-${i}`))?.publicKey,
        payload,
        `injection-shaped session owner must round-trip verbatim: ${payload}`,
      );

      const r = await store.hitRateLimit({ endpoint: "login", appId: "app1", identifier: payload }, 60, 5);
      assert(r.allowed, `injection-shaped rate-limit identifier must behave as plain data: ${payload}`);
    }

    // And it must not have matched everything: a `{"$gt":""}` used as a FILTER OBJECT
    // rather than a scalar value would match every row.
    assertEqual(
      await store.getSession("app1", '{"$gt":""}'),
      null,
      "NoSQL INJECTION: an operator-shaped key matched a row. Pass key/field only as " +
        "SCALAR STRING VALUES in a filter — never as a filter object, an update-document " +
        "key, or a path.",
    );
  });

  // === OPTIONAL: sweepExpired =====================================================

  if (opts.supportsSweep) {
    add("sweepExpired: removes expired entries only, and reports the count", async (store) => {
      assert(store.sweepExpired, "supportsSweep was declared but sweepExpired is absent");

      await store.putChallenge("app1", PK_A, "will-expire", 1);
      await store.putSession("app1", "live-hash", { publicKey: PK_A }, 3600);
      await advance(1000);

      const removed = await store.sweepExpired();
      assert(removed >= 1, "the sweep must report the entries it removed");

      // The live session must survive — a sweep that takes live rows is a logout storm.
      const live = await store.getSession("app1", "live-hash");
      assertEqual(live?.publicKey, PK_A, "sweepExpired must NEVER remove a live entry");
    });

    add("sweepExpired: respects `limit`", async (store) => {
      assert(store.sweepExpired, "supportsSweep was declared but sweepExpired is absent");
      for (let i = 0; i < 5; i++) await store.putChallenge("app1", `pk-${i}`, "x", 1);
      await advance(1000);

      const removed = await store.sweepExpired(2);
      assert(removed <= 2, `limit=2 must bound one batch, but ${removed} were removed`);
    });
  }

  return cases;
}
