// SqlAuthStore — the SQL engine (ADR-002).
//
// THIS FILE IS WHERE ALL THE CORRECTNESS LIVES. Every hazard that used to be the
// integrator's problem is solved here, once, for every SQL engine:
//
//   • expiry enforced on the READ path         → every SELECT carries `expires_at > ?`
//   • rate-limit window semantics              → ONE upsert template, with the CASE
//   • atomic challenge consume (anti-replay)   → DELETE…RETURNING, or a locking transaction
//   • no lost write on the email index         → PRIMARY KEY (email, app_id) + upsert
//   • email normalization                      → normalizeEmail() before the driver sees it
//   • collation / column sizing                → the dialect's DDL; the user never picks
//   • injection safety                         → templates + bound params, always
//   • fail closed                              → no try/catch. Errors propagate.
//
// A dialect author reads none of this. They declare `supportsReturning` and emit DDL.
import type { AuthStore, SessionValue, RateLimitBucket, RateLimitResult } from "../store.js";
import { normalizeEmail } from "../store.js";
import { sortWalletsBySlot, type UserData, type EncryptedWallet } from "../../core/types.js";
import type { SqlDialect, SqlDriver } from "./types.js";

export interface SqlAuthStoreOptions {
  /**
   * Clock used to evaluate expiry, in epoch ms. Injectable for tests.
   *
   * Expiry is evaluated against the APPLICATION's clock, not the database's — the engine
   * passes `now` as a bound parameter. That keeps the SQL identical across engines (no
   * `now()` vs `NOW(3)` vs `unixepoch()`) and makes expiry testable without sleeping.
   * The trade: app servers must have a sane clock (NTP). At session/challenge timescales
   * — minutes to hours — ordinary skew is irrelevant.
   */
  now?: () => number;
}

/** Strip the schema qualifier: `tetrac.ttc_users` → `ttc_users`. An upsert's DO UPDATE
 *  clause references the target row by its BARE table name on all three engines. */
const bare = (table: string): string => table.split(".").pop() as string;

/**
 * Coerce a rate-limit count, FAILING CLOSED.
 *
 * `Number(row?.count ?? 1)` read "the upsert returned nothing" as "first hit of a new
 * window" and let the request through — a rate limiter that cannot count was granting
 * permission, under exactly the conditions that broke it. The store contract requires the
 * opposite: no answer means throw, and the caller 500s.
 *
 * `checkRateLimit` has no try/catch, so throwing here is what fail-closed looks like.
 */
function countOrFailClosed(raw: unknown): number {
  const n = Number(raw);
  if (raw == null || !Number.isFinite(n)) {
    throw new Error(
      "[tetrac] rate-limit upsert returned no usable count — refusing to treat an " +
        "un-countable request as allowed.",
    );
  }
  return n;
}

export class SqlAuthStore implements AuthStore {
  private readonly now: () => number;

  constructor(
    private readonly driver: SqlDriver,
    private readonly dialect: SqlDialect,
    opts: SqlAuthStoreOptions = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
  }

  /** Build a statement, converting `?` placeholders to the dialect's positional form. */
  private sql(parts: TemplateStringsArray | string): string {
    const raw = typeof parts === "string" ? parts : parts.join("");
    let i = 0;
    return raw.replace(/\?/g, () => this.dialect.placeholder(i++));
  }

  private async run<T = Record<string, unknown>>(
    driver: SqlDriver,
    sql: string,
    params: readonly unknown[],
  ): Promise<T[]> {
    return driver.query<T>(this.sql(sql), params);
  }

  // === USERS =======================================================================

  async getUser(appId: string, publicKey: string): Promise<UserData | null> {
    const t = this.dialect.tables;
    const rows = await this.run<{ data: string; auth_token_hash: string | null }>(
      this.driver,
      `SELECT data, auth_token_hash FROM ${t.users} WHERE app_id = ? AND public_key = ?`,
      [appId, publicKey],
    );
    const row = rows[0];
    if (row?.data == null) return null;
    try {
      const user = JSON.parse(String(row.data)) as UserData;
      // Wallets live one-row-per-slot, so a slot write never rewrites the profile and two
      // concurrent writes to DIFFERENT slots cannot lose each other.
      const ws = await this.run<{ data: string }>(
        this.driver,
        `SELECT data FROM ${t.userWallets} WHERE app_id = ? AND public_key = ?`,
        [appId, publicKey],
      );
      user.wallets = sortWalletsBySlot(ws.map((w) => JSON.parse(String(w.data)) as EncryptedWallet));
      if (row.auth_token_hash != null) user.authTokenHash = String(row.auth_token_hash);
      return user;
    } catch {
      return null; // malformed value — fail safe rather than throwing
    }
  }

  /**
   * Upsert the record AND the email index, in ONE transaction.
   *
   * The KV port cannot do this (two round trips, no atomicity). Here we can, so we do:
   * a crash between the two writes cannot leave an account whose email doesn't resolve.
   *
   * The email index is keyed `(email, app_id)` — one ROW per tenant, not one row with a
   * field per tenant — so two concurrent registrations of the same email under different
   * appIds touch different rows and NEITHER can be lost. The old hash-merge race is
   * structurally impossible, not merely avoided.
   */
  async putUser(user: UserData): Promise<void> {
    const t = this.dialect.tables;
    const { wallets, authTokenHash, ...profile } = user;
    const data = JSON.stringify(profile);
    const tok = authTokenHash ?? null;

    await this.driver.transaction(async (tx) => {
      await this.run(
        tx,
        `INSERT INTO ${t.users} (app_id, public_key, data, auth_token_hash) VALUES (?, ?, ?, ?) ` +
          this.dialect.upsert(["app_id", "public_key"], ["data = ?", "auth_token_hash = ?"]),
        [user.appId, user.publicKey, data, tok, data, tok],
      );

      for (const w of wallets ?? []) {
        await this.run(
          tx,
          `INSERT INTO ${t.userWallets} (app_id, public_key, chain, role, data) VALUES (?, ?, ?, ?, ?) ` +
            this.dialect.upsert(["app_id", "public_key", "chain", "role"], ["data = ?"]),
          [user.appId, user.publicKey, w.chain, w.role, JSON.stringify(w), JSON.stringify(w)],
        );
      }

      if (user.email) {
        await this.run(
          tx,
          `INSERT INTO ${t.emailIndex} (email, app_id, public_key) VALUES (?, ?, ?) ` +
            this.dialect.upsert(["email", "app_id"], ["public_key = ?"]),
          [normalizeEmail(user.email), user.appId, user.publicKey, user.publicKey],
        );
      }
    });
  }

  /** One row, one slot — see AuthStore.putWalletSlot for why this is not a record rewrite. */
  async putWalletSlot(appId: string, publicKey: string, wallet: EncryptedWallet): Promise<void> {
    const t = this.dialect.tables;
    const data = JSON.stringify(wallet);
    await this.run(
      this.driver,
      `INSERT INTO ${t.userWallets} (app_id, public_key, chain, role, data) VALUES (?, ?, ?, ?, ?) ` +
        this.dialect.upsert(["app_id", "public_key", "chain", "role"], ["data = ?"]),
      [appId, publicKey, wallet.chain, wallet.role, data, data],
    );
  }

  /** One column. A login no longer rewrites the record, so it cannot race a wallet write. */
  async setSessionPointer(appId: string, publicKey: string, tokenHash: string): Promise<void> {
    const t = this.dialect.tables;
    await this.run(
      this.driver,
      `UPDATE ${t.users} SET auth_token_hash = ? WHERE app_id = ? AND public_key = ?`,
      [tokenHash, appId, publicKey],
    );
  }

  async getPublicKeyByEmail(appId: string, email: string): Promise<string | null> {
    const t = this.dialect.tables;
    const rows = await this.run<{ public_key: string }>(
      this.driver,
      `SELECT public_key FROM ${t.emailIndex} WHERE email = ? AND app_id = ?`,
      [normalizeEmail(email), appId],
    );
    return rows[0]?.public_key ?? null;
  }

  // === CHALLENGES ==================================================================

  async putChallenge(appId: string, publicKey: string, challenge: string, ttlSeconds: number): Promise<void> {
    const t = this.dialect.tables;
    const expiresAt = this.now() + ttlSeconds * 1000;
    await this.run(
      this.driver,
      `INSERT INTO ${t.challenges} (app_id, public_key, challenge, expires_at) VALUES (?, ?, ?, ?) ` +
        this.dialect.upsert(["app_id", "public_key", "challenge"], ["expires_at = ?"]),
      [appId, publicKey, challenge, expiresAt, expiresAt],
    );
  }

  /**
   * ATOMIC get-and-delete. This is the sole defense against challenge REPLAY: of N
   * concurrent callers, exactly ONE may observe the value.
   *
   * Note `expires_at > ?` — an expired challenge is invisible, with no sweeper required.
   */
  async takeChallenge(appId: string, publicKey: string, presented: string): Promise<boolean> {
    const t = this.dialect.tables;
    const now = this.now();

    // Consume THE presented value, not "whatever is stored for this identity". One
    // identity may hold several outstanding challenges — issuing must never invalidate one
    // already in flight — so burning one has to leave the others usable.
    if (this.dialect.supportsReturning) {
      // Postgres / SQLite: one statement. The engine guarantees atomicity.
      const rows = await this.run<{ challenge: string }>(
        this.driver,
        `DELETE FROM ${t.challenges} WHERE app_id = ? AND public_key = ? AND challenge = ? AND expires_at > ? RETURNING challenge`,
        [appId, publicKey, presented, now],
      );
      return rows.length > 0;
    }

    // MySQL has no DELETE…RETURNING. Lock the row, read it, delete it, commit — which is
    // exactly as atomic, and is why "MySQL is hard" is now a one-line dialect flag rather
    // than a footgun handed to an integrator.
    return this.driver.transaction(async (tx) => {
      const rows = await this.run<{ challenge: string }>(
        tx,
        `SELECT challenge FROM ${t.challenges} WHERE app_id = ? AND public_key = ? AND challenge = ? AND expires_at > ?` +
          this.dialect.forUpdate,
        [appId, publicKey, presented, now],
      );
      if (rows.length === 0) return false;
      await this.run(
        tx,
        `DELETE FROM ${t.challenges} WHERE app_id = ? AND public_key = ? AND challenge = ?`,
        [appId, publicKey, presented],
      );
      return true;
    });
  }

  // === SESSIONS ====================================================================

  async putSession(appId: string, tokenHash: string, value: SessionValue, ttlSeconds: number): Promise<void> {
    const t = this.dialect.tables;
    const expiresAt = this.now() + ttlSeconds * 1000;
    const fp = value.fingerprint ?? null;
    // publicKey and fingerprint are TYPED COLUMNS — not the KV port's "publicKey|fingerprint"
    // string, whose correctness rested on public keys never containing a '|'.
    await this.run(
      this.driver,
      `INSERT INTO ${t.sessions} (app_id, token_hash, public_key, fingerprint, expires_at) VALUES (?, ?, ?, ?, ?) ` +
        this.dialect.upsert(
          ["app_id", "token_hash"],
          ["public_key = ?", "fingerprint = ?", "expires_at = ?"],
        ),
      [appId, tokenHash, value.publicKey, fp, expiresAt, value.publicKey, fp, expiresAt],
    );
  }

  /** `expires_at > ?` is load-bearing: verifySession accepts any non-null value this
   *  returns, so a backend that leaked expired rows here would silently extend the life
   *  of every stolen bearer token. */
  async getSession(appId: string, tokenHash: string): Promise<SessionValue | null> {
    const t = this.dialect.tables;
    const rows = await this.run<{ public_key: string; fingerprint: string | null }>(
      this.driver,
      `SELECT public_key, fingerprint FROM ${t.sessions} WHERE app_id = ? AND token_hash = ? AND expires_at > ?`,
      [appId, tokenHash, this.now()],
    );
    const row = rows[0];
    if (!row) return null;
    return row.fingerprint == null
      ? { publicKey: row.public_key }
      : { publicKey: row.public_key, fingerprint: row.fingerprint };
  }

  async deleteSession(appId: string, tokenHash: string): Promise<void> {
    const t = this.dialect.tables;
    await this.run(this.driver, `DELETE FROM ${t.sessions} WHERE app_id = ? AND token_hash = ?`, [
      appId,
      tokenHash,
    ]);
  }

  // === RATE LIMITING ===============================================================

  /**
   * 🚨 The single most dangerous statement in the SDK.
   *
   * The `CASE` is what makes an EXPIRED row start a FRESH window instead of resuming a
   * stale count. Omit it — write the "obvious" `count = count + 1` — and a long-expired
   * counter at 15 keeps incrementing, never re-stamps its TTL, and that identifier (an IP,
   * an email, a public key) is rate-limited FOREVER. It passes every smoke test and only
   * appears days later, under sustained traffic.
   *
   * It is one statement, so the increment-and-decide is atomic and there is no read-modify-
   * write race. And it is written HERE, once, for every SQL engine — which is the entire
   * argument of ADR-002.
   */
  async hitRateLimit(
    bucket: RateLimitBucket,
    windowSeconds: number,
    maxAttempts: number,
  ): Promise<RateLimitResult> {
    const t = this.dialect.tables;
    const self = bare(t.rateLimits);
    const now = this.now();
    const fresh = now + windowSeconds * 1000;
    // appId is OPTIONAL on the bucket — the client-IP bucket is deliberately global across
    // endpoints and tenants. '' is its column value; the PK still holds.
    const appId = bucket.appId ?? "";

    const setClauses = [
      `count = CASE WHEN ${self}.expires_at <= ? THEN 1 ELSE ${self}.count + 1 END`,
      `expires_at = CASE WHEN ${self}.expires_at <= ? THEN ? ELSE ${self}.expires_at END`,
    ];
    const insert =
      `INSERT INTO ${t.rateLimits} (endpoint, app_id, identifier, count, expires_at) VALUES (?, ?, ?, 1, ?) ` +
      this.dialect.upsert(["endpoint", "app_id", "identifier"], setClauses);
    const params = [bucket.endpoint, appId, bucket.identifier, fresh, now, now, fresh];

    let count: number;
    if (this.dialect.supportsReturning) {
      const rows = await this.run<{ count: number | string }>(
        this.driver,
        `${insert} RETURNING count`,
        params,
      );
      count = countOrFailClosed(rows[0]?.count);
    } else {
      // MySQL: upsert, then read back inside the same transaction. The row is locked by the
      // upsert, so the SELECT cannot observe another writer's interleaved increment.
      count = await this.driver.transaction(async (tx) => {
        await this.run(tx, insert, params);
        const rows = await this.run<{ count: number | string }>(
          tx,
          `SELECT count FROM ${t.rateLimits} WHERE endpoint = ? AND app_id = ? AND identifier = ?`,
          [bucket.endpoint, appId, bucket.identifier],
        );
        return countOrFailClosed(rows[0]?.count);
      });
    }

    return { allowed: count <= maxAttempts, remaining: Math.max(0, maxAttempts - count) };
  }

  // === LIFECYCLE ===================================================================

  /**
   * Reclaim expired rows. SPACE ONLY — never the expiry authority; every read above
   * already filters. Wire it to a cron.
   *
   * This is not merely housekeeping: rate-limit rows embed **emails and IPs**. Redis
   * evicted them in 60s; a SQL table keeps them — and keeps them in every backup — until
   * something deletes them. That is a data-retention obligation.
   */
  async sweepExpired(limit = 1000): Promise<number> {
    const t = this.dialect.tables;
    const now = this.now();
    let removed = 0;
    for (const table of [t.sessions, t.challenges, t.rateLimits]) {
      const rows = await this.driver.query<{ affected?: number }>(
        this.dialect.deleteExpiredLimited(table, limit, 0),
        [now],
      );
      // With RETURNING (Postgres/SQLite) each deleted row comes back, so the row count IS
      // the count. Without it (MySQL) the driver reports `[{ affected: n }]`.
      removed += this.dialect.supportsReturning ? rows.length : Number(rows[0]?.affected ?? 0);
    }
    return removed;
  }

  async close(): Promise<void> {
    await this.driver.close?.();
  }
}
