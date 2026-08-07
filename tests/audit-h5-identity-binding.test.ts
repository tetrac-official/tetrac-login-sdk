// H-5(2) — identity-key squatting. Regression suite (grew out of the PoC that designed it).
//
// `/register` binds an identity `publicKey` with no proof that the caller holds the
// corresponding private key, for every authMethod except "wallet". The SDK's own model is
// that an identity key is EITHER generated client-side by this SDK OR the user's own web3
// wallet — but nothing enforces it, so a third party can plant a record at an address they
// do not control.
//
// Two defences, both now IN the SDK:
//   A. /register proves possession of the identity key (every authMethod, not just wallet)
//   B. connectWallet refuses to resolve a record the email/biometric path created
//
// §1 shows the plant is refused. §2 shows A's edges. §3 shows B as defence-in-depth.
// §4 shows the honest flows are untouched.
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { KvAuthStore } from "../src/storage/store";
import { DEFAULT_CONFIG } from "../src/core/config";
import { verifySolanaSignature } from "../src/server/signature";
import { consumeChallenge } from "../src/server/challenge";
import { walletLoginMessage } from "../src/core/index";
import { deriveAuthPublicKey } from "../src/client/authKey";
import { jreq } from "./_auth-helpers";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";

const ORIGIN = "https://test.example";
const APP = DEFAULT_CONFIG.appId;
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

function setup() {
  const storage = new MemoryAdapter();
  const store = new KvAuthStore(storage, DEFAULT_CONFIG.keyPrefixes);
  const h = createAuthHandlers({ storage, config: { origin: ORIGIN }, onWarning: () => {} });
  return { h, store };
}

/** Sign the standard wallet-login message with a keypair the caller actually holds. */
function signAs(kp: Keypair, challenge: string): string {
  return hex(
    nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge, ORIGIN)), kp.secretKey),
  );
}

/** The attacker's planted-record payload: victim's address, attacker's everything else. */
function plantBody(victimAddr: string, extra: Record<string, unknown> = {}) {
  return {
    publicKey: victimAddr,
    email: "attacker@evil.com",
    authPublicKey: deriveAuthPublicKey("aa".repeat(32)),
    authMethod: "email",
    wallets: [
      { chain: "solana", role: "funds", publicKey: "ATTACKER_SOL", encryptedSecret: "ct" },
      { chain: "evm", role: "funds", publicKey: "0xATTACKER_EVM", encryptedSecret: "ct" },
    ],
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// §1 — the attack, against the shipped code
// ---------------------------------------------------------------------------
describe("§1 — the plant is refused at the door", () => {
  it("🚨 an attacker CANNOT register at an address they do not control", async () => {
    const { h } = setup();
    const victim = Keypair.generate();
    const addr = victim.publicKey.toBase58();

    // /challenge is unauthenticated by design, so the attacker gets a challenge freely…
    const ch = await (await h.challenge(jreq({ publicKey: addr }))).json();
    // …but can only sign it with a key they actually hold.
    const attacker = Keypair.generate();
    const res = await h.register(
      jreq(plantBody(addr, { signature: signAs(attacker, ch.challenge), challenge: ch.challenge })),
    );

    expect(res.status).toBe(401);
    expect((await res.json()).error).toMatch(/Signature verification failed/);
  });

  it("🚨 omitting the proof is refused too", async () => {
    const { h } = setup();
    const res = await h.register(jreq(plantBody(Keypair.generate().publicKey.toBase58())));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/signature and challenge required/i);
  });

  it("🚨 so the victim's own address stays available to them", async () => {
    // The failure mode this closes: before the fix the attacker's record existed, the victim
    // authenticated into it, their own bundle was discarded, and the app rendered the
    // attacker's EVM address as a deposit address.
    const { h } = setup();
    const victim = Keypair.generate();
    const addr = victim.publicKey.toBase58();

    const chAtk = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const attacker = Keypair.generate();
    expect(
      (
        await h.register(
          jreq(plantBody(addr, { signature: signAs(attacker, chAtk.challenge), challenge: chAtk.challenge })),
        )
      ).status,
    ).toBe(401);

    const chVic = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const res = await h.connectWallet(
      jreq({ publicKey: addr, signature: signAs(victim, chVic.challenge), challenge: chVic.challenge }),
    );
    expect(res.status).toBe(201);
    const { user } = await res.json();
    expect(user.authMethod).toBe("wallet");
    expect(user.email).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §2 — FIX A: prove possession of the identity key at registration
// ---------------------------------------------------------------------------

/**
 * Simulates the proposed server-side check, using the real primitives. In the SDK this
 * would live in `register`, in the `else if (!body.authPublicKey)` branch's place.
 */
/** Registration now carries the proof natively — this just calls the real handler. */
async function registerWithProofOfPossession(
  h: ReturnType<typeof setup>["h"],
  _store: KvAuthStore,
  body: Record<string, unknown>,
): Promise<Response> {
  return h.register(jreq(body));
}

describe("§2 — FIX A blocks the plant at its source", () => {
  it("🚨 the attacker CANNOT register at an address whose key they lack", async () => {
    const { h, store } = setup();
    const victim = Keypair.generate();
    const addr = victim.publicKey.toBase58();

    // The attacker can freely obtain a challenge — /challenge is unauthenticated by design.
    const ch = await (await h.challenge(jreq({ publicKey: addr }))).json();

    // But they cannot sign it. Their best effort is signing with a key they DO hold.
    const attacker = Keypair.generate();
    const res = await registerWithProofOfPossession(
      h,
      store,
      plantBody(addr, { signature: signAs(attacker, ch.challenge), challenge: ch.challenge }),
    );

    expect(res.status).toBe(401);
    expect((await res.json()).error).toMatch(/Signature verification failed/);
  });

  it("🚨 omitting the proof entirely is also refused", async () => {
    const { h, store } = setup();
    const victim = Keypair.generate();
    const res = await registerWithProofOfPossession(h, store, plantBody(victim.publicKey.toBase58()));
    expect(res.status).toBe(400);
  });

  it("the HONEST client registers fine — it holds the key it just generated", async () => {
    // This is the whole point: signing is automatic and invisible, and that costs the
    // honest client nothing. The check gates on KEY POSSESSION, not on user attention.
    const { h, store } = setup();
    const identity = Keypair.generate(); // stands in for the SDK-generated bundle identity
    const addr = identity.publicKey.toBase58();

    const ch = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const res = await registerWithProofOfPossession(h, store, {
      publicKey: addr,
      email: "honest@example.com",
      authPublicKey: deriveAuthPublicKey("bb".repeat(32)),
      authMethod: "email",
      wallets: [{ chain: "solana", role: "funds", publicKey: addr, encryptedSecret: "ct" }],
      signature: signAs(identity, ch.challenge),
      challenge: ch.challenge,
    });

    expect(res.status).toBe(201);
  });

  it("a collision is answered BEFORE the proof is checked", async () => {
    // Not an oversight — it is what keeps the client's "auto" mode cheap. That mode
    // registers first and falls back to login on 409, so a RETURNING user hits /register on
    // every normal sign-in. Checking the collision first means their 409 costs no challenge
    // consume and no signature verification.
    //
    // (Challenge single-use itself is enforced by consumeChallenge and covered in
    // challenge-lockout.test.ts; it is unreachable from here because the collision wins.)
    const { h, store } = setup();
    const identity = Keypair.generate();
    const addr = identity.publicKey.toBase58();
    const ch = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const body = {
      publicKey: addr,
      email: "replay@example.com",
      authPublicKey: deriveAuthPublicKey("cc".repeat(32)),
      authMethod: "email",
      wallets: [],
      signature: signAs(identity, ch.challenge),
      challenge: ch.challenge,
    };

    expect((await registerWithProofOfPossession(h, store, body)).status).toBe(201);
    // Same bytes again: the record now exists, so the collision short-circuits at 409.
    expect((await registerWithProofOfPossession(h, store, body)).status).toBe(409);
  });
});

// ---------------------------------------------------------------------------
// §3 — FIX B: a wallet login must not resolve an email-path record
// ---------------------------------------------------------------------------

/** Simulates the proposed one-line guard at the top of connectWallet's record lookup. */
/** The guard is in connectWallet itself now — this just calls the real handler. */
async function connectWalletCrossMethodGuarded(
  h: ReturnType<typeof setup>["h"],
  _store: KvAuthStore,
  body: Record<string, unknown>,
): Promise<Response> {
  return h.connectWallet(jreq(body));
}

describe("§3 — FIX B stops the victim landing in a planted record", () => {
  it("🚨 a wallet login into an email-path record is refused", async () => {
    const { h, store } = setup();
    const victim = Keypair.generate();
    const addr = victim.publicKey.toBase58();
    // Fix A stops this record being CREATED, so plant it straight into storage — standing
    // in for an older record, or a hand-rolled client. B must still refuse to adopt it.
    await store.putUser({
      appId: APP,
      publicKey: addr,
      email: "attacker@evil.com",
      authMethod: "email",
      authPublicKey: deriveAuthPublicKey("aa".repeat(32)),
      wallets: [{ chain: "evm", role: "funds", publicKey: "0xATTACKER_EVM", encryptedSecret: "ct" }],
      createdAt: 0,
    });

    const ch = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const res = await connectWalletCrossMethodGuarded(h, store, {
      publicKey: addr,
      signature: signAs(victim, ch.challenge),
      challenge: ch.challenge,
    });

    expect(res.status).toBe(401);
    // The victim never sees the attacker's deposit addresses. They ARE denied their own
    // address on this deployment, which is why B is a mitigation and A is the fix.
  });

  it("a genuine wallet account still connects normally", async () => {
    const { h, store } = setup();
    const user = Keypair.generate();
    const addr = user.publicKey.toBase58();

    const ch1 = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const first = await connectWalletCrossMethodGuarded(h, store, {
      publicKey: addr,
      signature: signAs(user, ch1.challenge),
      challenge: ch1.challenge,
      wallets: [{ chain: "evm", role: "funds", publicKey: "0xMINE", encryptedSecret: "ct" }],
    });
    expect(first.status).toBe(201); // creates authMethod: "wallet"

    const ch2 = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const again = await connectWalletCrossMethodGuarded(h, store, {
      publicKey: addr,
      signature: signAs(user, ch2.challenge),
      challenge: ch2.challenge,
    });
    expect(again.status).toBe(200); // returning user, unaffected by the guard
  });
});

// ---------------------------------------------------------------------------
// §4 — the flows that must keep working
// ---------------------------------------------------------------------------
describe("§4 — no collateral damage", () => {
  it("A + B together: honest email register, then honest wallet register, coexist", async () => {
    const { h, store } = setup();

    const emailIdentity = Keypair.generate();
    const emailAddr = emailIdentity.publicKey.toBase58();
    const chA = await (await h.challenge(jreq({ publicKey: emailAddr }))).json();
    const emailReg = await registerWithProofOfPossession(h, store, {
      publicKey: emailAddr,
      email: "both@example.com",
      authPublicKey: deriveAuthPublicKey("dd".repeat(32)),
      authMethod: "email",
      wallets: [{ chain: "solana", role: "funds", publicKey: emailAddr, encryptedSecret: "ct" }],
      signature: signAs(emailIdentity, chA.challenge),
      challenge: chA.challenge,
    });
    expect(emailReg.status).toBe(201);

    const walletUser = Keypair.generate();
    const walletAddr = walletUser.publicKey.toBase58();
    const chB = await (await h.challenge(jreq({ publicKey: walletAddr }))).json();
    const walletReg = await connectWalletCrossMethodGuarded(h, store, {
      publicKey: walletAddr,
      signature: signAs(walletUser, chB.challenge),
      challenge: chB.challenge,
    });
    expect(walletReg.status).toBe(201);
  });

  it("🚨 with A in place, the victim's own address stays available to them", async () => {
    // The failure mode B alone leaves behind: the address is squatted and the real owner is
    // locked out. Under A the plant never happens, so the owner simply registers.
    const { h, store } = setup();
    const victim = Keypair.generate();
    const addr = victim.publicKey.toBase58();

    // Attacker tries and fails.
    const chAtk = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const attacker = Keypair.generate();
    expect(
      (
        await registerWithProofOfPossession(
          h,
          store,
          plantBody(addr, { signature: signAs(attacker, chAtk.challenge), challenge: chAtk.challenge }),
        )
      ).status,
    ).toBe(401);

    // The real owner connects their wallet — no squatted record in the way.
    const chVic = await (await h.challenge(jreq({ publicKey: addr }))).json();
    const res = await connectWalletCrossMethodGuarded(h, store, {
      publicKey: addr,
      signature: signAs(victim, chVic.challenge),
      challenge: chVic.challenge,
    });
    expect(res.status).toBe(201);
    expect((await res.json()).user.authMethod).toBe("wallet");
  });
});
