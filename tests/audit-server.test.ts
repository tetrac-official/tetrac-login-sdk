// CHARACTERIZATION TESTS — prove the auth/session/server findings against the
// CURRENT code, WITHOUT changing src/. They assert today's behavior so they PASS
// now and document each finding; invert the marked asserts after hardening.
//
// Findings: H5 (global rate-limit bucket), H6 (EVM login unimplemented + email
// bypass), AUTHSESSION-3 (targeted lockout), SERVERSIDE-1/8 (key-namespace
// collision + JSON.parse crash), SERVERSIDE-4 (unbounded import-wallet),
// SERVERSIDE-11 (no input validation), WEBAUTHN-1 (biometric = hash possession).
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { hashPasskey } from "../src/core/crypto";
import * as signature from "../src/server/signature";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
const SOL_PUB = "SoLPubKey1111111111111111111111111111111111";
const wallet = (i = 0) => ({ chain: "solana", role: `r${i}`, publicKey: `p${i}`, encryptedSecret: "c" });

async function registerEmail(h: ReturnType<typeof createAuthHandlers>, email: string, passkey: string, publicKey = SOL_PUB) {
  const res = await h.register(
    req({ publicKey, email, passkeyHash: hashPasskey(passkey), authMethod: "email", wallets: [wallet()] }),
  );
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
// ed25519-only is CORRECT — these are characterization tests of intended behavior,
// not a vulnerability. (Was finding H6 — now withdrawn / by-design.)
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

// The "EVM via email" path is NOT an EVM finding — it exercises two generic gaps:
// email registration needs no proof-of-control (SERVERSIDE-5) and publicKey is not
// format-validated (SERVERSIDE-11). The identity is an arbitrary unvalidated string.
describe("SERVERSIDE-5/11 — email register has no ownership proof and publicKey is unvalidated", () => {
  it("registers an arbitrary unvalidated publicKey via the email path with no proof of control (201)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const arbitrary = "0x" + "cd".repeat(20); // any string is accepted as the identity key
    const res = await h.register(
      req({ publicKey: arbitrary, email: "evm@x.com", passkeyHash: hashPasskey("k"), authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(201); // no signature, no email verification, no key-format check
  });
});

describe("AUTHSESSION-3 — per-identifier counter increments BEFORE auth ⇒ targeted account lockout", () => {
  it("an attacker who knows only the victim's email locks out the victim's own correct login", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage }); // default maxAttempts 10
    const email = "victim@example.com";
    await registerEmail(h, email, "real-passkey");

    // Attacker spams failed logins (wrong hash) for the victim's email until the bucket trips.
    let last: Response | undefined;
    for (let i = 0; i < 12; i++) {
      last = await h.login(req({ email, passkeyHash: hashPasskey("junk") }));
      if (last.status === 429) break;
    }
    expect(last!.status).toBe(429);

    // The victim's CORRECT-credential login is now also blocked.
    const victim = await h.login(req({ email, passkeyHash: hashPasskey("real-passkey") }));
    expect(victim.status).toBe(429);
  });
});

describe("SERVERSIDE-1/8 — key-namespace collision + unguarded JSON.parse", () => {
  it("an unauthenticated attacker can WRITE into the session-token keyspace (pubKey:session:*)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    // publicKey is never format-validated; "session:<x>" lands at storage key "pubKey:session:<x>",
    // the exact shape used for session tokens (session.ts sessionKey()).
    const res = await h.register(
      req({ publicKey: "session:forged-slot", email: "atk@x.com", passkeyHash: hashPasskey("k"), authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(201);
    const collided = await storage.get("pubKey:session:forged-slot");
    expect(collided).not.toBeNull();
    expect(collided!.startsWith("{")).toBe(true); // a user JSON blob now occupies the session namespace
  });

  it("colliding with a LIVE session value crashes register via unguarded JSON.parse (DoS)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const { body } = await registerEmail(h, "user@example.com", "pw"); // issues a session token
    const token = body.authToken;
    // The live session value at pubKey:session:<token> is a BARE publicKey string (not JSON).
    expect(await storage.get(`pubKey:session:${token}`)).toBe(body.publicKey);

    // Registering publicKey="session:<token>" makes getUserByPublicKey JSON.parse that bare string ⇒ throws.
    await expect(
      h.register(req({ publicKey: `session:${token}`, email: "atk@x.com", passkeyHash: hashPasskey("k"), authMethod: "email" })),
    ).rejects.toThrow();
  });
});

describe("SERVERSIDE-4 — import-wallet appends with NO total cap (record-bloat DoS)", () => {
  it("a session can grow its wallet array without bound", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const { body } = await registerEmail(h, "user@example.com", "pw"); // starts with 1 wallet
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

describe("SERVERSIDE-11 — no format/length validation on publicKey / email / passkeyHash", () => {
  it("accepts empty email, non-hex passkeyHash, and a whitespace publicKey (201)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({ publicKey: "   ", email: "", passkeyHash: "this is NOT hex!!", authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(201);
  });

  it("accepts a 100k-character publicKey (storage-waste)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const res = await h.register(
      req({ publicKey: "x".repeat(100_000), passkeyHash: "abc", authMethod: "email", wallets: [] }),
    );
    expect(res.status).toBe(201);
  });
});

describe("WEBAUTHN-1 — server never verifies a WebAuthn assertion; biometric login = possession of SHA-256(appKey)", () => {
  it("login succeeds with ONLY {email, passkeyHash} — no assertion / clientDataJSON / signature", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const appKey = "deadbeef".repeat(8); // a 256-bit PRF/gate secret
    const bioEmail = "bio_FAKECREDENTIALID@passkey.local";

    const reg = await h.register(
      req({ publicKey: "SoLBio1111111111111111111111111111111111111", email: bioEmail, passkeyHash: hashPasskey(appKey), authMethod: "biometric", wallets: [wallet()] }),
    );
    expect(reg.status).toBe(201); // registration also accepts a self-asserted hash (WEBAUTHN-2)

    // Anyone who knows SHA-256(appKey) authenticates from anywhere, no authenticator present:
    const login = await h.login(req({ email: bioEmail, passkeyHash: hashPasskey(appKey) }));
    expect(login.status).toBe(200);
  });
});
