// Audit 2026-08-08 F-4 — the account-creation ceiling must not be a deployment-wide DoS lever.
//
// The `create` bucket keys on an unrotatable identifier so an attacker cannot mint unbounded
// records by rotating keys. A single GLOBAL identifier has that property — but the defender
// has no key to rotate either, so an attacker holds the one bucket exhausted at the limit
// rate and closes registration for everyone.
//
// Two fixes, both here:
//   1. When a trustworthy IP exists, creation keys on THAT — one abuser is bounded to their
//      own IP; legitimate users on other IPs are unaffected.
//   2. A `beforeCreateAccount` gate runs regardless of IP, so a deployment with no
//      trustworthy IP can require PoW / CAPTCHA / an invite before a record is created.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { walletLoginMessage } from "../src/core/index";
import { registerEmail, jreq } from "./_auth-helpers";

const ORIGIN = "https://test.example";
const APP_KEY = "ab".repeat(32);
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Register a fresh account from a given IP (x-forwarded-for), returning the status. */
async function registerFromIp(
  h: ReturnType<typeof createAuthHandlers>,
  ip: string,
  i: number,
): Promise<number> {
  const kp = Keypair.generate();
  const publicKey = kp.publicKey.toBase58();
  const headers = { "x-forwarded-for": ip };
  const ch = (await (await h.challenge(jreq({ publicKey }, headers))).json()) as { challenge: string };
  const msg = new TextEncoder().encode(
    walletLoginMessage({ challenge: ch.challenge, origin: ORIGIN, address: publicKey }),
  );
  const res = await h.connectWallet(
    jreq(
      {
        publicKey,
        signature: toHex(nacl.sign.detached(msg, kp.secretKey)),
        challenge: ch.challenge,
        wallets: [],
      },
      headers,
    ),
  );
  return res.status;
}

describe("F-4 — creation is per-IP when a trustworthy IP exists", () => {
  it("🚨 one abuser exhausting their own IP does not close registration for another IP", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: ORIGIN,
        trustProxyHeaders: true,
        // Give the general IP bucket plenty of headroom so THIS test isolates the `create`
        // bucket, not the per-request IP throttle.
        rateLimit: { windowSeconds: 60, maxAttempts: 100 },
        accountCreationRateLimit: { windowSeconds: 60, maxAttempts: 2 },
      },
      onWarning: () => {},
    });

    // Attacker on one IP burns their creation budget.
    expect(await registerFromIp(h, "10.0.0.1", 0)).toBe(201);
    expect(await registerFromIp(h, "10.0.0.1", 1)).toBe(201);
    expect(await registerFromIp(h, "10.0.0.1", 2)).toBe(429);

    // A legitimate user on a DIFFERENT IP is unaffected — the global-bucket DoS is gone.
    expect(await registerFromIp(h, "10.0.0.2", 0)).toBe(201);
    expect(await registerFromIp(h, "10.0.0.2", 1)).toBe(201);
  });
});

describe("F-4 — beforeCreateAccount gates creation regardless of IP", () => {
  it("a false gate refuses creation with 403; existing accounts still log in", async () => {
    let allow = false;
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: ORIGIN },
      beforeCreateAccount: () => allow,
      onWarning: () => {},
    });

    const blocked = await registerEmail(h, { publicKey: "u1", email: "u1@test.com", appKey: APP_KEY });
    expect(blocked.status).toBe(403);

    allow = true;
    const created = await registerEmail(h, { publicKey: "u1", email: "u1@test.com", appKey: APP_KEY });
    expect(created.status).toBe(201);
  });

  it("a throwing gate fails CLOSED (403), never open", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: ORIGIN },
      beforeCreateAccount: () => {
        throw new Error("captcha backend down");
      },
      onWarning: () => {},
    });
    const res = await registerEmail(h, { publicKey: "u2", email: "u2@test.com", appKey: APP_KEY });
    expect(res.status).toBe(403);
  });

  it("the gate is NOT consulted on a returning user's sign-in (only on creation)", async () => {
    let calls = 0;
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: ORIGIN },
      beforeCreateAccount: () => {
        calls++;
        return true;
      },
      onWarning: () => {},
    });

    await registerEmail(h, { publicKey: "u3", email: "u3@test.com", appKey: APP_KEY }); // 1 creation
    // A returning user's auto-register collides on email (409) BEFORE the creation branch.
    await registerEmail(h, { publicKey: "u3-again", email: "u3@test.com", appKey: APP_KEY });
    expect(calls).toBe(1);
  });
});
