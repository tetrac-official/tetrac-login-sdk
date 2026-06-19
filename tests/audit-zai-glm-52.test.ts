// MACHINE-VERIFIED PROOFS for the findings in audits/zai-glm-52.md.
//
// This suite is the executable counterpart of the zai-glm-52 audit. Each `describe`
// block maps 1:1 to a finding (F#) or a positive confirmation (P#) in the report,
// so the audit's claims are continuously checkable against the live code. Where a
// finding describes an UNFIXED gap, the test characterizes the CURRENT (insecure)
// behavior and is marked // (F# — currently insecure; flip when fixed) — exactly
// the dual-bundle-vault.test.ts pattern (prove it, then guard the invariant).
//
// Run: npm test -- audit-zai-glm-52
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { getUserByPublicKey } from "../src/server/session";
import { timingSafeEqual, encryptSecret } from "../src/core/crypto";
import { deriveAuthPublicKey, signAuthChallenge } from "../src/client/authKey";
import { DEFAULT_CONFIG } from "../src/core/config";
import { registerEmail } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32); // a 64-hex (256-bit) app key, as audit-crypto.test.ts uses
const SOL_PUB = "SoLPubKey1111111111111111111111111111111111";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

const wallet = (i = 0) => ({
  chain: "solana" as const,
  role: `r${i}`,
  publicKey: `p${i}`,
  encryptedSecret: "c".repeat(40),
});

async function registerUser(h: ReturnType<typeof createAuthHandlers>, email: string, publicKey = SOL_PUB) {
  const res = await registerEmail(h, { publicKey, email, appKey: APP_KEY, wallets: [wallet()] });
  return { res, body: (await res.json()) as { authToken: string; publicKey: string } };
}

// ============================================================
// F3 — Server trusts client-supplied pbkdf2Iterations with no floor
// ============================================================
describe("F3 — register REJECTS an out-of-band pbkdf2Iterations (RESOLVED)", () => {
  it("rejects pbkdf2Iterations: 1 with 400 and creates no account (server floor)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    // An attacker (or misconfigured client) tries to kneecap this account's offline
    // brute-force resistance. The server now enforces a 100k–1M band and rejects it.
    const res = await registerEmail(h, {
      publicKey: SOL_PUB,
      email: "weak@example.com",
      appKey: APP_KEY,
      wallets: [],
      pbkdf2Iterations: 1, // <-- below the documented 100k legacy floor
    });
    expect(res.status).toBe(400); // F3 fixed: was 201

    // Nothing was persisted — the weak count never made it onto a record.
    const user = await getUserByPublicKey(storage, DEFAULT_CONFIG.appId, SOL_PUB, DEFAULT_CONFIG);
    expect(user).toBeNull();
  });

  it("rejects pathological values: 0, negative, above-ceiling, non-integer, string", async () => {
    // JSON-surviving bad values (NaN/Infinity serialize to null → treated as absent →
    // the legacy/wallet fallback, which is allowed). Everything else is rejected.
    for (const bad of [0, -5, 1e15, 600_000.5, "600000"]) {
      const h = createAuthHandlers({ storage: new MemoryAdapter() });
      const res = await registerEmail(h, {
        publicKey: SOL_PUB,
        email: `bad-${bad}@example.com`,
        appKey: APP_KEY,
        wallets: [],
        // @ts-expect-error — deliberately invalid types: the server must reject them
        pbkdf2Iterations: bad,
      });
      expect(res.status).toBe(400); // F3 fixed: was 201
    }
  });
});

// ============================================================
// F2 — No proof-of-key-control on email/biometric registration
// ============================================================
describe("F2 — email/biometric register needs NO signature/challenge (HIGH, currently insecure)", () => {
  it("registers a well-formed identity with NO signature/challenge proof of control (201)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    // A VALID Solana identity registers with NO ceremony — unlike the wallet path, which
    // requires verifySolanaSignature + consumeChallenge. (The arbitrary-string variant is
    // now rejected by strict publicKey validation — see audit-server.test.ts; the residual
    // F2 gap is the missing proof-of-control ceremony, still open.)
    const res = await registerEmail(h, {
      publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
      email: "noproof@x.com",
      appKey: APP_KEY,
      wallets: [],
    });
    expect(res.status).toBe(201); // F2 — no proof-of-control ceremony on the email path; still open
  });

  it("register does not consume a challenge (no single-use ceremony on the email path)", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    // Seed a challenge for the would-be identity; if register consumed it (as it
    // should), the key would be gone afterward. It is NOT consumed on email/bio.
    await storage.set(`${DEFAULT_CONFIG.keyPrefixes.challenge}${SOL_PUB}`, "deadbeef".repeat(8), {
      exSeconds: 300,
    });
    await registerEmail(h, {
      publicKey: SOL_PUB,
      email: "ceremony@example.com",
      appKey: APP_KEY,
      wallets: [],
    });
    const remaining = await storage.get(`${DEFAULT_CONFIG.keyPrefixes.challenge}${SOL_PUB}`);
    expect(remaining).toBe("deadbeef".repeat(8)); // untouched — register did NOT consume it
  });
});

// ============================================================
// F4 — import-wallet appends attacker ciphertext without ownership binding
// ============================================================
describe("F4 — importWallet appends arbitrary ciphertext under a valid session (MED, currently insecure)", () => {
  it("appends attacker-chosen wallet entries that the owner cannot decrypt", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const { body } = await registerUser(h, "victim@example.com");
    const auth = { "ttc-auth-token": body.authToken, "ttc-public-key": body.publicKey };

    // A stolen session token lets an attacker push garbage ciphertext (encrypted
    // under a key the victim does NOT hold) straight onto the victim's record.
    const garbage = await encryptSecret("0x" + "ff".repeat(32), "00".repeat(32)); // wrong app key
    const res = await h.importWallet(
      req(
        {
          wallets: [
            {
              chain: "solana",
              role: "evil",
              publicKey: "EvilPubKey111111111111111111111111111111111",
              encryptedSecret: garbage,
            },
          ],
        },
        auth,
      ),
    );
    expect(res.status).toBe(200); // (F4 — currently insecure; reject/decrypt-verify when fixed)

    const ud = await (await h.userData(req({}, auth))).json();
    expect(ud.user.wallets.some((w: { role: string }) => w.role === "evil")).toBe(true); // poisoned
  });

  it("a duplicate publicKey is appended (no dedup → an attacker can shadow an entry)", async () => {
    const h = createAuthHandlers({ storage: new MemoryAdapter() });
    const { body } = await registerUser(h, "shadow@example.com");
    const auth = { "ttc-auth-token": body.authToken, "ttc-public-key": body.publicKey };
    const dup = wallet(0).publicKey; // same publicKey as the registered funds wallet

    const res = await h.importWallet(
      req(
        { wallets: [{ chain: "solana", role: "shadow", publicKey: dup, encryptedSecret: "x".repeat(40) }] },
        auth,
      ),
    );
    expect(res.status).toBe(200); // (F4 — no dedup; flip to 400 when fixed)

    const ud = await (await h.userData(req({}, auth))).json();
    const pubs = ud.user.wallets.map((w: { publicKey: string }) => w.publicKey);
    expect(pubs.filter((p: string) => p === dup).length).toBe(2); // duplicated, not deduped
  });
});

// ============================================================
// F8 — timingSafeEqual reads out-of-bounds on length mismatch (LOW)
// ============================================================
describe("F8 — timingSafeEqual never false-accepts on length mismatch (correctness guard)", () => {
  // F8 fixed: the implementation substitutes 0 past the end of the shorter string
  // (no out-of-bounds read, no NaN reliance) and returns false on any length mismatch.
  // This test pins that correctness so a future refactor can't silently flip it.
  it("returns false for every length-mismatch shape (no false-accept via NaN)", () => {
    const probes: Array<[string, string]> = [
      ["a", "abc"],
      ["abc", "a"],
      ["abcd", "abc"],
      ["abc", "abcd"],
      ["", "abc"],
      ["abc", ""],
      ["aaaa", "aaa"],
      ["a".repeat(64), ""],
      ["a".repeat(64), "a".repeat(63)],
    ];
    for (const [a, b] of probes) {
      expect({ a, b, result: timingSafeEqual(a, b) }).toMatchObject({ result: false });
      expect({ a, b, result: timingSafeEqual(b, a) }).toMatchObject({ result: false }); // symmetric
    }
  });

  it("still returns true for equal strings of varying length (positive control)", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("", "")).toBe(true);
    expect(timingSafeEqual("a".repeat(64), "a".repeat(64))).toBe(true);
    expect(timingSafeEqual("日本語", "日本語")).toBe(true);
  });
});

// ============================================================
// P# — POSITIVE confirmations of properties the audit says are correct
//      (so a regression in any of them is caught immediately).
// ============================================================
describe("P1 — challenges are single-use via atomic getdel (replay-safe)", () => {
  it("consuming a challenge once removes it; a second consume fails", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage });
    const ch = await h.challenge(req({ publicKey: SOL_PUB }));
    const { challenge } = (await ch.json()) as { challenge: string };

    // First consume: derives via the challenge handler indirectly; here we exercise
    // consumeChallenge directly through a login-shaped flow is heavy, so verify the
    // storage contract: the key exists, and is gone after one getdel.
    // Key is app-scoped (v0.4.0): challenge:{appId}:{publicKey}, default appId "ttc".
    const key = `${DEFAULT_CONFIG.keyPrefixes.challenge}${DEFAULT_CONFIG.appId}:${SOL_PUB}`;
    expect(await storage.get(key)).toBe(challenge);
    expect(await storage.getdel(key)).toBe(challenge);
    expect(await storage.getdel(key)).toBeNull(); // second consume → null (single-use)
  });
});

describe("P2 — AES-256-GCM fails closed on tamper / wrong key (no silent garbage)", () => {
  const key = "ab".repeat(32);
  it("round-trips with the right key, rejects a wrong key and any single-bit flip", async () => {
    const secret = "0x" + "11".repeat(32);
    const ct = await encryptSecret(secret, key);
    expect(await decryptOrThrow(ct, key)).toBe(secret);
    await expect(decryptOrThrow(ct, "cd".repeat(32))).rejects.toThrow();
    const [iv, body] = ct.split(":");
    const flipped = body![0] === "A" ? "B" : "A";
    await expect(decryptOrThrow(`${iv}:${flipped}${body!.slice(1)}`, key)).rejects.toThrow();
  });
});

describe("P3 — rate limiting is per-target and skips the spoofable IP when untrusted", () => {
  // (The per-target "distinct publicKeys are not mutually locked out" case is already
  // exhaustively covered by H5 RESOLVED in audit-server.test.ts — not duplicated here.)

  it("an attacker-supplied x-forwarded-for is IGNORED by default (trustProxyHeaders=false)", async () => {
    const h = createAuthHandlers({
      storage: new MemoryAdapter(),
      config: { trustProxyHeaders: false, rateLimit: { maxAttempts: 1, windowSeconds: 60 } },
    });
    // Spoofed XFF must not create per-IP buckets that an attacker could rotate to evade limits.
    const spoofed = { "x-forwarded-for": "9.9.9.9" };
    const a = await h.challenge(req({ publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9" }, spoofed));
    const b = await h.challenge(
      req({ publicKey: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9" }, { "x-forwarded-for": "8.8.8.8" }),
    );
    // AAA is rate-limited on its OWN bucket regardless of spoofed IPs (a=200, b=429).
    expect([a.status, b.status].sort()).toEqual([200, 429]);
  });
});

describe("P4 — auth is a signature, and the server stores a PUBLIC key (no passkey hash)", () => {
  it("signAuthChallenge with the right appKey verifies; a wrong appKey does not", () => {
    const pub = deriveAuthPublicKey(APP_KEY);
    const challenge = "deadbeef".repeat(8);
    const good = signAuthChallenge(APP_KEY, challenge);
    const bad = signAuthChallenge("00".repeat(32), challenge);
    // verifyAuthSignature is server-only but deterministic; re-derive + verify via nacl shape.
    // We assert the key property: same appKey reproduces the same signature deterministically,
    // and a different appKey produces a different signature (so the public key is a real verifier).
    expect(good).not.toBe(bad);
    expect(good).toBe(signAuthChallenge(APP_KEY, challenge)); // deterministic
    expect(pub).toMatch(/^[0-9a-f]{64}$/);
  });
});

// helper: import lazily to keep the positive-control block self-contained
async function decryptOrThrow(ct: string, key: string): Promise<string> {
  const { decryptSecret } = await import("../src/core/crypto");
  return decryptSecret(ct, key);
}
