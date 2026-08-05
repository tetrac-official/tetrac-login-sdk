// H-2(b) (audit.md) — a ceiling on account creation that the caller cannot rotate past.
//
// Every other rate-limit bucket is keyed on an identifier lifted from the request body:
// `/register` uses `body.email ?? body.publicKey`, `/connect-wallet` uses `body.publicKey`.
// A fresh `Keypair.generate()` per request is a fresh bucket, so the counter is always 1
// and the documented 10/60s limit never fires — audit.md measured 40/40 anonymous
// registrations accepted. The client-IP bucket that WOULD catch this is skipped because
// `trustProxyHeaders` defaults to false, and it cannot be turned on safely without a proxy
// that overwrites `x-forwarded-for` (otherwise the attacker just picks the IP too).
//
// `accountCreationRateLimit` is one bucket for the whole deployment — no appId, no
// identifier — so there is nothing to rotate.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { DEFAULT_CONFIG } from "../src/core/config";
import { walletLoginMessage } from "../src/core/index";
import { registerEmail, loginEmail, jreq } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32);
const ORIGIN = "https://test.example";

function handlers(storage: MemoryAdapter, over: Record<string, unknown> = {}) {
  return createAuthHandlers({ storage, config: { origin: ORIGIN, ...over } });
}

const freshKey = () => Keypair.generate().publicKey.toBase58();

describe("account creation ceiling", () => {
  it("defaults to 2 per 60s", () => {
    expect(DEFAULT_CONFIG.accountCreationRateLimit).toEqual({ windowSeconds: 60, maxAttempts: 2 });
  });

  it("🚨 rotating the email does NOT buy more registrations", async () => {
    const h = handlers(new MemoryAdapter());

    // Each request carries a brand-new email AND a brand-new public key, so every
    // per-target bucket sees its first hit. Only the global ceiling can stop this.
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await registerEmail(h, {
        publicKey: freshKey(),
        email: `burst${i}@example.com`,
        appKey: APP_KEY,
        wallets: [],
      });
      statuses.push(res.status);
    }

    expect(statuses.slice(0, 2)).toEqual([201, 201]); // the budget
    expect(statuses.slice(2)).toEqual([429, 429, 429]); // everything after it
  });

  it("🚨 rotating the appId does not buy more either — the bucket is not app-scoped", async () => {
    const h = handlers(new MemoryAdapter());

    const mk = (appId: string, i: number) =>
      registerEmail(h, {
        appId,
        publicKey: freshKey(),
        email: `tenant${i}@example.com`,
        appKey: APP_KEY,
        wallets: [],
      });

    expect((await mk("app.one", 0)).status).toBe(201);
    expect((await mk("app.two", 1)).status).toBe(201);
    // A third appId would be a third namespace — and, before this, a third free record.
    expect((await mk("app.three", 2)).status).toBe(429);
  });

  it("🚨 /connect-wallet is capped too — a valid signature is not a licence to create", async () => {
    const h = handlers(new MemoryAdapter());

    const connect = async () => {
      const kp = Keypair.generate();
      const publicKey = kp.publicKey.toBase58();
      const { challenge } = await (await h.challenge(jreq({ publicKey }))).json();
      const sig = Buffer.from(
        nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge, ORIGIN)), kp.secretKey),
      ).toString("hex");
      return h.connectWallet(jreq({ publicKey, signature: sig, challenge, wallets: [] }));
    };

    expect((await connect()).status).toBe(201);
    expect((await connect()).status).toBe(201);
    expect((await connect()).status).toBe(429); // keypairs are free; records are not
  });

  it("a RETURNING user is never charged — the ceiling counts creations, not /register hits", async () => {
    // The client's "auto" mode registers first and falls back to login on 409, so an
    // ordinary sign-in hits /register. Charging those would make a 2/min creation ceiling
    // behave as a 2/min LOGIN ceiling and lock out the whole deployment.
    const h = handlers(new MemoryAdapter());
    const publicKey = freshKey();
    const email = "returning@example.com";

    expect((await registerEmail(h, { publicKey, email, appKey: APP_KEY, wallets: [] })).status).toBe(201);

    // Budget is now 1 of 2. Repeated returning sign-ins must not consume any of it.
    // (Kept under 10 so the PER-TARGET /register bucket — 10/60s on this email, charged on
    // every hit including a 409 — isn't what ends the loop.)
    for (let i = 0; i < 5; i++) {
      const dup = await registerEmail(h, { publicKey: freshKey(), email, appKey: APP_KEY, wallets: [] });
      expect(dup.status).toBe(409); // "Account already exists" — no record created
      expect((await loginEmail(h, { email, appKey: APP_KEY })).status).toBe(200);
    }

    // The one remaining creation is still available.
    expect(
      (
        await registerEmail(h, {
          publicKey: freshKey(),
          email: "new@example.com",
          appKey: APP_KEY,
          wallets: [],
        })
      ).status,
    ).toBe(201);
  });

  it("the ceiling is configurable by the application owner", async () => {
    const h = handlers(new MemoryAdapter(), {
      accountCreationRateLimit: { windowSeconds: 60, maxAttempts: 4 },
    });

    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await registerEmail(h, {
        publicKey: freshKey(),
        email: `cfg${i}@example.com`,
        appKey: APP_KEY,
        wallets: [],
      });
      statuses.push(res.status);
    }
    expect(statuses).toEqual([201, 201, 201, 201, 429]);
  });

  it("the window drains — a full budget is not a permanent lockout", async () => {
    let now = 1_000_000;
    const storage = new MemoryAdapter(() => now);
    const h = handlers(storage);

    const mk = (i: number) =>
      registerEmail(h, {
        publicKey: freshKey(),
        email: `win${i}@example.com`,
        appKey: APP_KEY,
        wallets: [],
      });

    expect((await mk(0)).status).toBe(201);
    expect((await mk(1)).status).toBe(201);
    expect((await mk(2)).status).toBe(429);

    now += 61_000; // the window elapses

    expect((await mk(3)).status).toBe(201);
  });
});
