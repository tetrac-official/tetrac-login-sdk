// CHARACTERIZATION TESTS — auth/session/server findings, updated for v0.2.1.
// Several findings are now RESOLVED by the signature-auth refactor (Change 3):
// email/biometric accounts authenticate by signing a challenge with a derived
// ed25519 auth keypair; the server stores only the public key (no passkey hash).
//
// Findings, now all RESOLVED: H5 (global rate-limit bucket → per-target buckets),
// AUTHSESSION-3 (targeted lockout → verify-first/penalize-on-failure), SERVERSIDE-1/8
// (key-namespace collision + JSON.parse crash), SERVERSIDE-4 (unbounded import-wallet),
// SERVERSIDE-11 (no input validation), WEBAUTHN-1 (login now requires a challenge
// signature, not a bearer hash).
import { createAuthHandlers } from "../src/server/routes";
import { KvAuthStore } from "../src/storage/store";
import { hashSessionToken } from "../src/core/crypto";
import { MemoryAdapter } from "../src/storage/memory";
import { getUserByPublicKey } from "../src/server/session";
import { DEFAULT_CONFIG } from "../src/core/config";
import * as signature from "../src/server/signature";
import { registerEmail, loginEmail } from "./_auth-helpers";
import { deriveAuthPublicKey } from "../src/client/authKey";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
const SOL_PUB = "SoLPubKey1111111111111111111111111111111111";
const APP_KEY = "ab".repeat(32); // fixed 64-hex app key for the signature-auth flow
// A wallet in one of the four (chain, role) slots a record may hold. Roles are closed
// ("funds" | "signing") and a record holds at most one wallet per slot, so `i` indexes
// the slot space rather than growing a list.
const SLOTS = [
  { chain: "solana", role: "funds" },
  { chain: "solana", role: "signing" },
  { chain: "evm", role: "funds" },
  { chain: "evm", role: "signing" },
] as const;
const wallet = (i = 0) => ({ ...SLOTS[i % SLOTS.length], publicKey: `p${i}`, encryptedSecret: "c" });

async function registerUser(h: ReturnType<typeof createAuthHandlers>, email: string, publicKey = SOL_PUB) {
  const res = await registerEmail(h, { publicKey, email, appKey: APP_KEY, wallets: [wallet()] });
  return { res, body: await res.json() };
}

describe("H5 RESOLVED — challenge rate limiting is per-target, not a shared global bucket", () => {
  it("distinct REGISTERED publicKeys get independent buckets ⇒ one abuser can't lock out everyone", async () => {
    // The concern is that flooding ONE real account's /challenge must not lock out OTHERS.
    // That per-account distinctness applies to keys that resolve to a record — so seed the
    // three as real wallet accounts. Unregistered keys deliberately SHARE one global bucket
    // now (audit 2026-08-08 F-5, see audit-f5-*), so they are the wrong fixture here.
    const store = new KvAuthStore(new MemoryAdapter(), DEFAULT_CONFIG.keyPrefixes);
    const A = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
    const B = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
    const C = "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse";
    for (const publicKey of [A, B, C]) {
      await store.putUser({ appId: "ttc", publicKey, authMethod: "wallet", wallets: [], createdAt: 1 });
    }
    const h = createAuthHandlers({
      store,
      config: { origin: "https://test.example", rateLimit: { maxAttempts: 2, windowSeconds: 60 } },
    });
    // trustProxyHeaders defaults false ⇒ the SDK no longer gates on the shared "unknown"
    // IP bucket; each /challenge is rate-limited on its OWN resolved-publicKey counter, so
    // hammering one target can't exhaust a global bucket and lock out the others.
    expect((await h.challenge(req({ publicKey: A }))).status).toBe(200);
    expect((await h.challenge(req({ publicKey: B }))).status).toBe(200);
    expect((await h.challenge(req({ publicKey: C }))).status).toBe(200); // NO global lockout
    // The per-target limit still bites when a SINGLE target is flooded…
    expect((await h.challenge(req({ publicKey: A }))).status).toBe(200); // AAA #2 (== limit)
    expect((await h.challenge(req({ publicKey: A }))).status).toBe(429); // AAA #3 (> limit)
    // …and a different target is unaffected by that flood.
    expect((await h.challenge(req({ publicKey: B }))).status).toBe(200);
  });
});

describe("challenge UNKNOWN-email rate limiting (WI-4 enumeration hardening)", () => {
  it("untrusted: repeated /challenge for the SAME unknown email is throttled (was previously unlimited)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example", rateLimit: { maxAttempts: 2, windowSeconds: 60 } },
    });
    // An unknown email now answers 200 with an unstored DUMMY challenge rather than 400 —
    // the 400 was an account-existence oracle (L-3). What this case pins is unchanged: the
    // limit runs BEFORE resolution, so probes for unknown emails are charged rather than
    // escaping the counter entirely.
    const probe = () => h.challenge(req({ email: "ghost@example.com" }));
    expect((await probe()).status).toBe(200);
    expect((await probe()).status).toBe(200);
    expect((await probe()).status).toBe(429); // 3rd same-email probe throttled
  });

  it("trusted proxy: unknown-email probes from one source IP are IP-throttled across DIFFERENT emails", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: {
        origin: "https://test.example",
        trustProxyHeaders: true,
        // The per-IP bucket carries its own limit now (F-7); size THAT to exercise it.
        ipRateLimit: { maxAttempts: 2, windowSeconds: 60 },
      },
    });
    // This is the case requester-keying exists for: DIFFERENT emails, one source. Per-target
    // keying gave each probed address its own counter and never saw the sweep at all.
    const probe = (email: string) => h.challenge(req({ email }, { "x-forwarded-for": "1.2.3.4" }));
    expect((await probe("a@ghost.com")).status).toBe(200);
    expect((await probe("b@ghost.com")).status).toBe(200);
    expect((await probe("c@ghost.com")).status).toBe(429); // IP bucket curbs enumeration
  });
});

// NOTE (maintainer-confirmed scope): EVM keypairs are INTERNAL, client-generated
// signing wallets (useEvmSigner / viem LocalAccount), NOT external auth identities.
// External wallet LOGIN is Solana-only by design, so verifySolanaSignature being
// ed25519-only is CORRECT — these are characterization tests of intended behavior.
describe("BY DESIGN — external wallet auth is Solana-only (EVM is internal-signing-only)", () => {
  it("only a Solana ed25519 verifier exists; there is intentionally no external EVM verifier", () => {
    expect((signature as any).verifyEvmSignature).toBeUndefined();
    expect(typeof signature.verifySolanaSignature).toBe("function");
  });

  it("a 0x EVM address fails closed on the wallet-auth path — rejected at publicKey validation (400)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const evm = "0x" + "ef".repeat(20);
    expect(signature.verifySolanaSignature(evm, "00".repeat(64), "challenge", "https://test.example")).toBe(
      false,
    );
    const res = await h.loginWallet(
      req({ publicKey: evm, signature: "00".repeat(64), challenge: "x".repeat(64) }),
    );
    // Strict Solana-only validation now rejects a 0x identity up front (was a 401 sig-fail).
    expect(res.status).toBe(400);
  });
});

// SERVERSIDE-11 (publicKey format) is now ENFORCED — the identity must be a Solana
// ed25519 key. SERVERSIDE-5 (no email-ownership proof) remains a documented residual:
// a *well-formed* identity still registers without proving control of the email.
describe("SERVERSIDE-11 RESOLVED (publicKey format) / SERVERSIDE-5 residual (email ownership)", () => {
  it("rejects an arbitrary non-Solana publicKey (e.g. an EVM 0x address) with 400", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const arbitrary = "0x" + "cd".repeat(20); // not a Solana ed25519 key
    const res = await h.register(
      req({
        publicKey: arbitrary,
        email: "evm@x.com",
        authPublicKey: deriveAuthPublicKey(APP_KEY),
        authMethod: "email",
        wallets: [],
        // Dummy: publicKey validation runs BEFORE the possession proof.
        signature: "00".repeat(64),
        challenge: "a".repeat(64),
      }),
    );
    expect(res.status).toBe(400); // publicKey format is now validated (SERVERSIDE-11)
  });

  it("still registers a well-formed Solana identity with NO email-ownership proof (SERVERSIDE-5 residual)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await registerEmail(h, {
      publicKey: "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB",
      email: "noproof@x.com",
      appKey: APP_KEY,
      wallets: [],
    });
    expect(res.status).toBe(201); // email ownership is an integrator obligation, still not enforced
  });
});

describe("AUTHSESSION-3 RESOLVED — a valid login is never blocked by an attacker's failed attempts", () => {
  it("the victim's correct login still succeeds after an attacker exhausts the failure limit", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example", rateLimit: { maxAttempts: 3, windowSeconds: 60 } },
    });
    const email = "victim@example.com";
    await registerUser(h, email);

    // Attacker spams junk logins for the victim's email. Each FAILS auth (bad signature),
    // and only failed attempts feed the counter, so after maxAttempts the attacker is
    // throttled. Crucially, a junk signature never reaches consumeChallenge, so it can't
    // even burn a pending challenge.
    let last: Response | undefined;
    for (let i = 0; i < 6; i++) {
      last = await h.login(req({ email, signature: "00", challenge: "00" }));
    }
    expect(last!.status).toBe(429); // attacker throttled

    // The victim's OWN correct login still succeeds — auth is verified BEFORE the rate
    // counter is touched, so a valid signature bypasses the attacker's failure throttle.
    const victim = await loginEmail(h, { email, appKey: APP_KEY });
    expect(victim.status).toBe(200);
  });
});

describe("SERVERSIDE-1/8 RESOLVED — sessions are namespaced disjointly; JSON.parse is guarded", () => {
  it("a 'session:'-prefixed publicKey cannot collide with the session-token store", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });
    // The victim's live session now lives under "session:<token>" (NOT "pubKey:session:<token>").
    const { body } = await registerUser(h, "victim@example.com");
    const token = body.authToken;
    expect(await storage.get(`session:ttc:${hashSessionToken(token)}`)).toBe(body.publicKey);

    // An attacker can't even register publicKey="session:<token>" — strict Solana
    // validation rejects it (400, ':' isn't base58), so the namespace collision the
    // disjoint prefixes already prevented is now impossible at the door. Session intact.
    const atk = await h.register(
      req({
        publicKey: `session:${token}`,
        email: "atk@x.com",
        authPublicKey: deriveAuthPublicKey(APP_KEY),
        authMethod: "email",
        wallets: [],
        signature: "00".repeat(64),
        challenge: "a".repeat(64),
      }),
    );
    expect(atk.status).toBe(400);
    expect(await storage.get(`session:ttc:${hashSessionToken(token)}`)).toBe(body.publicKey); // intact
  });

  it("getUserByPublicKey answers null for an absent record", async () => {
    const storage = new MemoryAdapter();
    // A stray STRING key is invisible to the hash read — the record hash simply does not
    // exist, so this is the ABSENT case and null is correct. An existing-but-unparseable
    // record is the opposite case and must THROW, not read as absent — audit 2026-08-08
    // F-1 (see audit-f1-getuser-fail-closed.test.ts): null here is what let connect-wallet
    // re-create the record and overwrite its wallet keys.
    await storage.set("pubKey:ttc:weird", "not-json{");
    const user = await getUserByPublicKey(
      new KvAuthStore(storage, DEFAULT_CONFIG.keyPrefixes),
      "ttc",
      "weird",
    );
    expect(user).toBeNull();
  });
});

describe("SERVERSIDE-4 RESOLVED — the record is slot-bounded, so import cannot grow it", () => {
  it("🚨 repeated imports never grow the record past its four (chain, role) slots", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const { body } = await registerUser(h, "user@example.com"); // starts with 1 wallet
    const auth = { "ttc-auth-token": body.authToken, "ttc-public-key": body.publicKey };
    const full = SLOTS.map((_, i) => wallet(i)); // one wallet per slot

    // The old cap was a COUNT (64) over an append. That let a session holder add 63
    // entries of ~8 KB ciphertext. The bound is now structural: there are four slots and
    // an import replaces one, so the record cannot grow no matter how often this runs.
    for (let i = 0; i < 5; i++) {
      expect((await h.importWallet(req({ wallets: full }, auth))).status).toBe(200);
    }

    const ud = await (await h.userData(req({}, auth))).json();
    expect(ud.user.wallets.length).toBe(SLOTS.length);

    // …and every slot is unique.
    const slots = ud.user.wallets.map((w: { chain: string; role: string }) => `${w.chain}:${w.role}`);
    expect(new Set(slots).size).toBe(SLOTS.length);
  });

  it("a payload with more entries than there are slots is rejected", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const { body } = await registerUser(h, "toomany@example.com");
    const auth = { "ttc-auth-token": body.authToken, "ttc-public-key": body.publicKey };
    const tooMany = [...SLOTS.map((_, i) => wallet(i)), { ...wallet(0), publicKey: "extra" }];

    expect((await h.importWallet(req({ wallets: tooMany }, auth))).status).toBe(400);
  });
});

describe("SERVERSIDE-11 RESOLVED — input validation rejects malformed publicKey / email (400)", () => {
  it("rejects a whitespace-padded publicKey", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await h.register(
      req({
        publicKey: "   ",
        email: "a@b.com",
        authPublicKey: "a".repeat(64),
        authMethod: "email",
        wallets: [],
      }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a 100k-character publicKey (length bound)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await h.register(
      req({
        publicKey: "x".repeat(100_000),
        email: "a@b.com",
        authPublicKey: "a".repeat(64),
        authMethod: "email",
        wallets: [],
      }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a malformed email", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const res = await h.register(
      req({
        publicKey: SOL_PUB,
        email: "not-an-email",
        authPublicKey: "a".repeat(64),
        authMethod: "email",
        wallets: [],
      }),
    );
    expect(res.status).toBe(400);
  });
});

describe("WEBAUTHN-1 RESOLVED — login requires a challenge signature, not a bearer hash", () => {
  it("a login without a signature is rejected; a valid challenge signature succeeds", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { origin: "https://test.example" },
    });
    const appKey = "deadbeef".repeat(8); // a 256-bit PRF/gate secret (biometric appKey)
    const bioEmail = "bio_FAKECREDENTIALID@passkey.local";

    const reg = await registerEmail(h, {
      publicKey: "SoLBio1111111111111111111111111111111111111",
      email: bioEmail,
      appKey,
      wallets: [wallet()],
    });
    expect(reg.status).toBe(201); // stores an ed25519 auth public key, never a passkey hash

    // No signature/challenge → 400: login is no longer a bearer-hash compare.
    const noSig = await h.login(req({ email: bioEmail }));
    expect(noSig.status).toBe(400);

    // A valid challenge signature with the same appKey authenticates.
    const ok = await loginEmail(h, { email: bioEmail, appKey });
    expect(ok.status).toBe(200);
  });
});
