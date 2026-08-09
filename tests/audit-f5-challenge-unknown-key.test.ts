// Audit 2026-08-08 F-5 — /challenge for an UNKNOWN public key must not write unbounded storage.
//
// The per-identifier challenge bucket is keyed on the caller-supplied public key, so an
// attacker generating a fresh keypair per request got a fresh counter every time and could
// write an unbounded set of stored challenges (each a row, TTL-bounded) plus one rate-limit
// row per rotated key. A registered account keys per-account (not rotatable), but an unknown
// key did not.
//
// Fix: with no trustworthy IP, an unknown key keys on ONE global bucket. A fresh keypair per
// request no longer buys a fresh counter — the write is bounded. Registration still works:
// an unknown key still receives a STORED challenge (registration proves possession of a key
// with no record yet), just rate-limited globally rather than per-rotated-key.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { KvAuthStore } from "../src/storage/store";
import { DEFAULT_CONFIG } from "../src/core/config";
import { walletLoginMessage } from "../src/core/index";
import { registerEmail, jreq } from "./_auth-helpers";

const ORIGIN = "https://test.example";
const APP_KEY = "ab".repeat(32);
const freshKey = () => Keypair.generate().publicKey.toBase58();
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function handlers(store: KvAuthStore, over: Record<string, unknown> = {}) {
  return createAuthHandlers({
    store,
    config: { origin: ORIGIN, ...over },
    onWarning: () => {},
  });
}

describe("F-5 — rotating a fresh key per /challenge does NOT buy unbounded stored challenges", () => {
  it("🚨 unknown keys share one global bucket, so a rotation flood is throttled", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(new KvAuthStore(storage, DEFAULT_CONFIG.keyPrefixes), {
      rateLimit: { windowSeconds: 60, maxAttempts: 5 },
    });

    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) {
      statuses.push((await h.challenge(jreq({ publicKey: freshKey() }))).status);
    }

    // Old behavior: 12 fresh keys = 12 fresh counters = zero 429s. Now they collide.
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    expect(statuses.slice(0, 5).every((s) => s === 200)).toBe(true);
  });

  it("a REGISTERED account's own /challenge is never throttled by an unknown-key flood", async () => {
    const store = new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    const h = handlers(store, { rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(h, { publicKey: "known", email: "known@test.com", appKey: APP_KEY });

    // Exhaust the global unknown-key bucket.
    for (let i = 0; i < 10; i++) await h.challenge(jreq({ publicKey: freshKey() }));

    // The real account keys on its own publicKey, a different bucket entirely.
    expect((await h.challenge(jreq({ email: "known@test.com" }))).status).toBe(200);
  });
});

describe("F-5 — registration still works: an unknown key gets a usable stored challenge", () => {
  it("connect-wallet (register a brand-new wallet) completes end-to-end", async () => {
    const store = new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    const h = handlers(store);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    // /challenge for a key with no record yet must still STORE a challenge…
    const ch = (await (await h.challenge(jreq({ publicKey }))).json()) as { challenge: string };
    const msg = new TextEncoder().encode(walletLoginMessage(ch.challenge, ORIGIN));
    // …or this consume would fail and registration would be impossible.
    const res = await h.connectWallet(
      jreq({
        publicKey,
        signature: toHex(nacl.sign.detached(msg, kp.secretKey)),
        challenge: ch.challenge,
        wallets: [],
      }),
    );
    expect(res.status).toBe(201);
  });

  it("with a trustworthy IP, unknown-key challenges are bounded per-IP, not globally", async () => {
    const store = new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    const h = handlers(store, {
      trustProxyHeaders: true,
      // The per-IP bucket carries its own limit (F-7); size THAT for the per-IP bound.
      ipRateLimit: { windowSeconds: 60, maxAttempts: 3 },
    });

    // One IP hammering fresh keys is throttled by its OWN IP bucket…
    const a: number[] = [];
    for (let i = 0; i < 6; i++) {
      a.push((await h.challenge(jreq({ publicKey: freshKey() }, { "x-forwarded-for": "10.0.0.9" }))).status);
    }
    expect(a).toContain(429);

    // …while a different IP registering a new key is unaffected (no global bucket in play).
    const other = await h.challenge(jreq({ publicKey: freshKey() }, { "x-forwarded-for": "10.0.0.10" }));
    expect(other.status).toBe(200);
  });
});
