// CHARACTERIZATION TESTS — auth/session/server findings, updated for v0.2.1.
// Several findings are now RESOLVED by the signature-auth refactor (Change 3):
// email/biometric accounts authenticate by signing a challenge with a derived
// ed25519 auth keypair; the server stores only the public key (no passkey hash).
//
// Findings: H5 (global rate-limit bucket), AUTHSESSION-3 (targeted lockout),
// SERVERSIDE-1/8 (key-namespace collision + JSON.parse crash), SERVERSIDE-4
// (unbounded import-wallet), SERVERSIDE-11 (no input validation), WEBAUTHN-1
// (RESOLVED — login now requires a challenge signature, not a bearer hash).
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import * as signature from "../src/server/signature";
import { registerEmail, loginEmail } from "./_auth-helpers";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
const SOL_PUB = "SoLPubKey1111111111111111111111111111111111";
const APP_KEY = "ab".repeat(32); // fixed 64-hex app key for the signature-auth flow
const wallet = (i = 0) => ({ chain: "solana", role: `r${i}`, publicKey: `p${i}`, encryptedSecret: "c" });

async function registerUser(h: ReturnType<typeof createAuthHandlers>, email: string, publicKey = SOL_PUB) {
  const res = await registerEmail(h, { publicKey, email, appKey: APP_KEY, wallets: [wallet()] });
  return { res, body: await res.json() };
}

describe("H5 — per-IP rate limiting collapses to ONE global 'unknown' bucket by default", () => {
  it("distinct clients/targets share one bucket on /challenge ⇒ one client locks out everyone", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { rateLimit: { maxAttempts: 2, windowSeconds: 60 } },
    });
    // trustProxyHeaders defaults false ⇒ clientIp() === "unknown" for ALL clients, and /challenge
    // passes no per-identity identifier, so these three DIFFERENT public keys share one counter.
    expect((await h.challenge(req({ publicKey: "AAA" }))).status).toBe(200);
    expect((await h.challenge(req({ publicKey: "BBB" }))).status).toBe(200);
    expect((await h.challenge(req({ publicKey: "CCC" }))).status).toBe(429); // global lockout
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

  it("a 0x EVM address fails closed (401) on the wallet-auth path — intended", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const evm = "0x" + "ef".repeat(20);
    expect(signature.verifySolanaSignature(evm, "00".repeat(64), "challenge")).toBe(false);
    await h.challenge(req({ publicKey: evm }));
    const res = await h.loginWallet(req({ publicKey: evm, signature: "00".repeat(64), challenge: "x".repeat(64) }));
    expect(res.status).toBe(401);
  });
});

// Not an EVM finding — it exercises two generic gaps: email registration needs no
// proof-of-control (SERVERSIDE-5) and publicKey is not format-validated (SERVERSIDE-11).
describe("SERVERSIDE-5/11 — email register has no ownership proof and publicKey is unvalidated", () => {
  it("registers an arbitrary unvalidated publicKey via the email path with no proof of control (201)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const arbitrary = "0x" + "cd".repeat(20); // any string is accepted as the identity key
    const res = await registerEmail(h, { publicKey: arbitrary, email: "evm@x.com", appKey: APP_KEY, wallets: [] });
    expect(res.status).toBe(201); // no signature, no email verification, no key-format check
  });
});

describe("AUTHSESSION-3 — per-identifier counter increments BEFORE auth ⇒ targeted account lockout", () => {
  it("an attacker who knows only the victim's email locks out the victim's own correct login", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() }); // default maxAttempts 10
    const email = "victim@example.com";
    await registerUser(h, email);

    // Attacker spams junk logins for the victim's email; the per-email rate counter is
    // incremented in rateLimited() BEFORE the challenge/signature is ever verified.
    let last: Response | undefined;
    for (let i = 0; i < 12; i++) {
      last = await h.login(req({ email, signature: "00", challenge: "00" }));
      if (last.status === 429) break;
    }
    expect(last!.status).toBe(429);

    // The victim's own valid login is now denied too — rate-limited before any
    // signature check (429 at /challenge, surfacing as 400 downstream in loginEmail).
    const victim = await loginEmail(h, { email, appKey: APP_KEY });
    expect(victim.status).not.toBe(200);
  });
});

describe("SERVERSIDE-1/8 — key-namespace collision + unguarded JSON.parse", () => {
  it("an unauthenticated attacker can WRITE into the session-token keyspace (pubKey:session:*)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    // publicKey is never format-validated; "session:<x>" lands at storage key "pubKey:session:<x>",
    // the exact shape used for session tokens (session.ts sessionKey()).
    const res = await registerEmail(h, { publicKey: "session:forged-slot", email: "atk@x.com", appKey: APP_KEY, wallets: [] });
    expect(res.status).toBe(201);
    const collided = await storage.get("pubKey:session:forged-slot");
    expect(collided).not.toBeNull();
    expect(collided!.startsWith("{")).toBe(true); // a user JSON blob now occupies the session namespace
  });

  it("colliding with a LIVE session value crashes register via unguarded JSON.parse (DoS)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const { body } = await registerUser(h, "user@example.com"); // issues a session token
    const token = body.authToken;
    // The live session value at pubKey:session:<token> is a BARE publicKey string (not JSON).
    expect(await storage.get(`pubKey:session:${token}`)).toBe(body.publicKey);

    // Registering publicKey="session:<token>" makes getUserByPublicKey JSON.parse that bare string ⇒ throws.
    await expect(
      registerEmail(h, { publicKey: `session:${token}`, email: "atk@x.com", appKey: APP_KEY, wallets: [] }),
    ).rejects.toThrow();
  });
});

describe("SERVERSIDE-4 — import-wallet appends with NO total cap (record-bloat DoS)", () => {
  it("a session can grow its wallet array without bound", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const { body } = await registerUser(h, "user@example.com"); // starts with 1 wallet
    const auth = { "ttc-auth-token": body.authToken, "ttc-public-key": body.publicKey };
    const batch = Array.from({ length: 16 }, (_, i) => wallet(i)); // max per-batch is enforced (16)

    for (let i = 0; i < 5; i++) {
      const r = await h.importWallet(req({ wallets: batch }, auth));
      expect(r.status).toBe(200);
    }
    const ud = await (await h.userData(req({}, auth))).json();
    expect(ud.user.wallets.length).toBe(81); // 1 + 5*16 — no total ceiling exists
  });
});

describe("SERVERSIDE-11 RESOLVED — input validation rejects malformed publicKey / email (400)", () => {
  it("rejects a whitespace-padded publicKey", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({ publicKey: "   ", email: "a@b.com", authPublicKey: "a".repeat(64), authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a 100k-character publicKey (length bound)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({ publicKey: "x".repeat(100_000), email: "a@b.com", authPublicKey: "a".repeat(64), authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects a malformed email", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({ publicKey: SOL_PUB, email: "not-an-email", authPublicKey: "a".repeat(64), authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(400);
  });
});

describe("WEBAUTHN-1 RESOLVED — login requires a challenge signature, not a bearer hash", () => {
  it("a login without a signature is rejected; a valid challenge signature succeeds", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
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
