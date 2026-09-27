// M-1 (audit.md) / H-6 — issuing a challenge must not invalidate one already in flight.
//
// `putChallenge` stored ONE challenge per (appId, publicKey) and overwrote it silently.
// `/challenge` is unauthenticated and accepts any public key or email, so anyone who could
// NAME an account could destroy the challenge its owner was mid-way through signing:
//
//   attacker requests a challenge for the victim's email  →  victim's login: 401
//
// The window is not tight. At securityLevel 2 the client spends ~7s in PBKDF2 deriving the
// app key before it can sign, so a single request per attempt — from anywhere, with no
// credentials — holds a named user out of their own account indefinitely.
//
// Challenges now accumulate per identity and are consumed BY VALUE, each expiring on its
// own. There is deliberately no eviction: evicting the oldest would restore the attack
// (flood the set, push the victim's out).
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { walletLoginMessage } from "../src/core/index";
import { deriveAuthPublicKey, signAuthChallenge } from "../src/client/authKey";
import { registerEmail, jreq } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32);
const ORIGIN = "https://test.example";

const handlers = (storage: MemoryAdapter) =>
  createAuthHandlers({
    storage,
    config: { origin: ORIGIN, accountCreationRateLimit: { windowSeconds: 60, maxAttempts: 50 } },
  });

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** The wallet-login signature `kp` produces for `challenge`, naming its own public key. */
const signLogin = (kp: Keypair, challenge: string) =>
  toHex(
    nacl.sign.detached(
      new TextEncoder().encode(
        walletLoginMessage({ challenge, origin: ORIGIN, address: kp.publicKey.toBase58() }),
      ),
      kp.secretKey,
    ),
  );

describe("M-1 — an attacker cannot invalidate a victim's in-flight challenge", () => {
  it("🚨 email login: the victim's challenge still works after an attacker requests one", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const email = "victim@example.com";

    expect(
      (
        await registerEmail(h, {
          publicKey: Keypair.generate().publicKey.toBase58(),
          email,
          appKey: APP_KEY,
          wallets: [],
        })
      ).status,
    ).toBe(201);

    // The victim fetches a challenge and begins deriving — ~7s of PBKDF2 at level 2.
    const victimChallenge = (await (await h.challenge(jreq({ email }))).json()).challenge as string;

    // Mid-derivation, the attacker requests a challenge for the SAME account. No
    // credentials, no session — just the email, which is all they need to name the target.
    const attackerChallenge = (await (await h.challenge(jreq({ email }))).json()).challenge as string;
    expect(attackerChallenge).not.toBe(victimChallenge);

    // The victim now submits a signature over the challenge they were given.
    const res = await h.login(
      jreq({ email, signature: signAuthChallenge(APP_KEY, victimChallenge), challenge: victimChallenge }),
    );
    expect(res.status).toBe(200);
  });

  it("🚨 wallet login: same, for the Web3 path", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    const first = (await (await h.challenge(jreq({ publicKey }))).json()).challenge as string;
    await h.challenge(jreq({ publicKey })); // attacker's request lands in between

    const sig = signLogin(kp, first);
    const res = await h.connectWallet(jreq({ publicKey, signature: sig, challenge: first, wallets: [] }));
    expect(res.status).toBe(201);
  });

  it("a flood of attacker challenges does not evict the victim's", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    const mine = (await (await h.challenge(jreq({ publicKey }))).json()).challenge as string;
    for (let i = 0; i < 9; i++) await h.challenge(jreq({ publicKey }));

    const sig = signLogin(kp, mine);
    expect(
      (await h.connectWallet(jreq({ publicKey, signature: sig, challenge: mine, wallets: [] }))).status,
    ).toBe(201);
  });

  it("each challenge is still single-use — consuming one does not free it for replay", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    const c = (await (await h.challenge(jreq({ publicKey }))).json()).challenge as string;
    const sig = signLogin(kp, c);
    const body = { publicKey, signature: sig, challenge: c, wallets: [] };

    expect((await h.connectWallet(jreq(body))).status).toBe(201);
    // Replaying the exact same (challenge, signature) must fail — the value is gone.
    expect((await h.connectWallet(jreq(body))).status).toBe(401);
  });

  it("a malformed challenge is rejected before it can become a storage key", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    const real = (await (await h.challenge(jreq({ publicKey }))).json()).challenge as string;

    // The presented value is part of the lookup key now, so anything that is not exactly
    // what generateChallenge() mints is refused up front.
    // ("" is a MISSING field, refused earlier with 400 — a different path.)
    // [presented, signed]. "a"×63 and "x"×5000 are valid SIWS nonces, so they are signed as
    // presented and only the challenge-shape check can refuse them. "not-hex" and ":extra"
    // cannot appear in a login message at all, so they travel with a genuine signature over
    // the real challenge instead.
    const cases: [string, string][] = [
      ["not-hex", real],
      ["a".repeat(63), "a".repeat(63)],
      [`${"a".repeat(64)}:extra`, real],
      ["x".repeat(5000), "x".repeat(5000)],
    ];
    for (const [bad, signed] of cases) {
      const sig = signLogin(kp, signed);
      const res = await h.connectWallet(jreq({ publicKey, signature: sig, challenge: bad, wallets: [] }));
      expect(res.status).toBe(401);
    }

    // None of them consumed the real challenge.
    const res = await h.connectWallet(
      jreq({ publicKey, signature: signLogin(kp, real), challenge: real, wallets: [] }),
    );
    expect(res.status).toBe(201);
  });

  it("registration still binds the auth key it was given", async () => {
    // Guard against the fix loosening /register: an email account's authPublicKey must
    // still be the one that can log in.
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const email = "bind@example.com";
    await registerEmail(h, {
      publicKey: Keypair.generate().publicKey.toBase58(),
      email,
      appKey: APP_KEY,
      wallets: [],
    });

    const c = (await (await h.challenge(jreq({ email }))).json()).challenge as string;
    const wrongKey = "cd".repeat(32);
    expect(deriveAuthPublicKey(wrongKey)).not.toBe(deriveAuthPublicKey(APP_KEY));

    const bad = await h.login(jreq({ email, signature: signAuthChallenge(wrongKey, c), challenge: c }));
    expect(bad.status).toBe(401);
  });
});
