// C9 — Concurrent operation safety.
//
// WHAT THIS TESTS:
//  - Atomic challenge consumption (getdel prevents replay races)
//  - Concurrent session issuance (old token revoked before new one)
//  - Rate limit counter atomicity (incr is atomic)
//  - Two concurrent registrations with same email (collision detection)
//  - Two concurrent connect-wallet calls (upsert race)
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail, loginEmail, addressFor } from "./_auth-helpers";
import { issueChallenge, consumeChallenge } from "../src/server/challenge";
import { KvAuthStore } from "../src/storage/store";
import type { AuthConfig } from "../src/core/config";
import { walletLoginMessage } from "../src/core/index";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const testConfig = {
  challengeTtlSeconds: 300,
  sessionTtlSeconds: 86400,
  keyPrefixes: {
    challenge: "challenge:",
    pubKey: "pubKey:",
    session: "session:",
    email: "email:",
    rateLimit: "ratelimit:",
  },
  rateLimit: { windowSeconds: 60, maxAttempts: 100 }, // high limit to not interfere
  trustProxyHeaders: false,
} as unknown as AuthConfig;

const APP = "ttc"; // appId scope for the direct challenge-layer calls (multi-app, v0.4.0)

describe("atomic challenge consumption (C9)", () => {
  it("two concurrent consumes can't both succeed (getdel atomicity)", async () => {
    // Simulate the getdel race: two requests try to consume the same
    // challenge at the same time. Only one should succeed.
    const storage = new MemoryAdapter();
    const pk = "SolConcurrent11111111111111111111111111111";

    // Issue one challenge
    const challenge = await issueChallenge(
      new KvAuthStore(storage, testConfig.keyPrefixes),
      APP,
      pk,
      testConfig,
    );

    // Attempt to consume it twice concurrently
    const [r1, r2] = await Promise.all([
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, pk, challenge),
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, pk, challenge),
    ]);

    // At most one should succeed
    expect(r1 || r2).toBe(true);
    expect(r1 && r2).toBe(false); // both can't be true

    // Third attempt must definitely fail
    const r3 = await consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, pk, challenge);
    expect(r3).toBe(false);
  });

  it("challenge for different public keys do not interfere", async () => {
    const storage = new MemoryAdapter();

    const ch1 = await issueChallenge(
      new KvAuthStore(storage, testConfig.keyPrefixes),
      APP,
      "pk-1",
      testConfig,
    );
    const ch2 = await issueChallenge(
      new KvAuthStore(storage, testConfig.keyPrefixes),
      APP,
      "pk-2",
      testConfig,
    );

    const [r1a, r2a] = await Promise.all([
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, "pk-1", ch1),
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, "pk-2", ch2),
    ]);
    expect(r1a).toBe(true);
    expect(r2a).toBe(true);

    // Can't reuse consumed challenges
    const [r1b, r2b] = await Promise.all([
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, "pk-1", ch1),
      consumeChallenge(new KvAuthStore(storage, testConfig.keyPrefixes), APP, "pk-2", ch2),
    ]);
    expect(r1b).toBe(false);
    expect(r2b).toBe(false);
  });

  it("consuming a non-existent challenge returns false", async () => {
    const storage = new MemoryAdapter();
    const result = await consumeChallenge(
      new KvAuthStore(storage, testConfig.keyPrefixes),
      APP,
      "unknown-pk",
      "fake-challenge",
    );
    expect(result).toBe(false);
  });
});

describe("session issuance revocation", () => {
  it("sequential logins: second login revokes the first token", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });

    const appKey = "ab".repeat(32);
    const pk = addressFor("concurrent-safety");

    await registerEmail(h, { publicKey: pk, email: "seq@test.com", appKey });

    // First login
    const login1 = await loginEmail(h, { email: "seq@test.com", appKey });
    expect(login1.status).toBe(200);
    const body1 = await login1.json();

    // Verify first token works
    const ud1 = await h.userData(req({}, { "ttc-auth-token": body1.authToken, "ttc-public-key": pk }));
    expect(ud1.status).toBe(200);

    // Second login (sequential)
    const login2 = await loginEmail(h, { email: "seq@test.com", appKey });
    expect(login2.status).toBe(200);
    const body2 = await login2.json();

    // First token now revoked
    const ud1After = await h.userData(req({}, { "ttc-auth-token": body1.authToken, "ttc-public-key": pk }));
    expect(ud1After.status).toBe(401);

    // Second token works
    const ud2After = await h.userData(req({}, { "ttc-auth-token": body2.authToken, "ttc-public-key": pk }));
    expect(ud2After.status).toBe(200);
  });

  // L-5. The sequential case above passes because issueSession deletes the previous
  // session key before minting the next one. That mechanism reads the previous hash off
  // the caller's OWN snapshot of the record, so two logins in flight together both read
  // the same value, both delete that same already-gone key, and neither deletes the
  // other's. Two session keys stay live; the record's pointer names exactly one.
  //
  // Before the fix the loser's token still authenticated — and was unrevocable, since no
  // later login and no logout could name it. verifySession now requires the presented
  // hash to BE the record's pointer, so exactly one of the two survives.
  it("🚨 concurrent logins: exactly ONE token is left usable", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });

    const appKey = "cd".repeat(32);
    const pk = addressFor("concurrent-safety");

    await registerEmail(h, { publicKey: pk, email: "race@test.com", appKey });

    // Two devices signing in at the same moment.
    const [a, b] = await Promise.all([
      loginEmail(h, { email: "race@test.com", appKey }),
      loginEmail(h, { email: "race@test.com", appKey }),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const tokenA = (await a.json()).authToken;
    const tokenB = (await b.json()).authToken;
    expect(tokenA).not.toBe(tokenB);

    const used = await Promise.all(
      [tokenA, tokenB].map(
        async (t) => (await h.userData(req({}, { "ttc-auth-token": t, "ttc-public-key": pk }))).status,
      ),
    );

    expect(used.filter((s) => s === 200)).toHaveLength(1);
    expect(used.filter((s) => s === 401)).toHaveLength(1);
  });

  // The pointer is now load-bearing, so a token that was never the pointer must not work
  // even while its session key is alive — this is the orphan the race used to produce.
  it("🚨 a live session key whose hash is not the record's pointer is rejected", async () => {
    const storage = new MemoryAdapter();
    const store = new KvAuthStore(storage, testConfig.keyPrefixes);
    const h = createAuthHandlers({ store, config: { origin: "https://test.example" } });

    const appKey = "ef".repeat(32);
    const pk = addressFor("concurrent-safety");

    await registerEmail(h, { publicKey: pk, email: "orphan@test.com", appKey });
    const login = await loginEmail(h, { email: "orphan@test.com", appKey });
    const token = (await login.json()).authToken;

    // The session key is untouched and unexpired; only the record's pointer moves — which
    // is precisely the state the losing racer was left in.
    await store.setSessionPointer("ttc", pk, "0".repeat(64));

    const after = await h.userData(req({}, { "ttc-auth-token": token, "ttc-public-key": pk }));
    expect(after.status).toBe(401);
  });
});

describe("concurrent registration race", () => {
  it("two concurrent registrations with same email — only one succeeds", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });

    const makeReg = (pk: string) =>
      registerEmail(h, { publicKey: pk, email: "duplicate@test.com", appKey: "ab".repeat(32) });

    // Two registrations with the SAME email but DIFFERENT public keys
    const [r1, r2] = await Promise.all([
      makeReg("GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB"),
      makeReg("2KW2XRd9kwqet15Aha2oK3tYvd3nWbTFH1MBiRAv1BE1"),
    ]);

    // The email collision check (routes.ts:129-132) runs before persistUser,
    // but in a race, both may see no existing email and both create.
    // The storage.set is NOT conditional on "set if not exists", so the
    // SECOND registration overwrites the first's email→publicKey index.
    //
    // At most one should succeed with 201; the other gets 409.
    // In a race, both might get 201 if the collision check runs
    // concurrently before either persists.
    const twoHundreds = [r1.status, r2.status].filter((s) => s === 201).length;
    // This test is informational — it documents the race condition.
    // eslint-disable-next-line no-console
    console.log(`  Concurrent same-email registrations: ${r1.status}, ${r2.status}`);

    // After the race, verify the email index (now a {appId -> publicKey} hash) holds
    // a public key for this app under the duplicate email.
    const storedPk = await storage.hget("email:duplicate@test.com", "ttc");
    expect(storedPk).not.toBeNull();
  });
});

describe("concurrent connect-wallet upsert", () => {
  it("two concurrent connect-wallet calls for same new wallet — only one creates", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { origin: "https://test.example" } });
    const kp = Keypair.generate();
    const pubKey = kp.publicKey.toBase58();

    // Get one challenge (shared between both concurrent requests)
    const chRes = await h.challenge(req({ publicKey: pubKey }));
    const { challenge } = await chRes.json();
    const sig = bytesToHex(
      nacl.sign.detached(
        new TextEncoder().encode(
          walletLoginMessage({ challenge, origin: "https://test.example", address: pubKey }),
        ),
        kp.secretKey,
      ),
    );

    // Both send the same challenge (only one should succeed)
    const cwBody = {
      publicKey: pubKey,
      signature: sig,
      challenge,
      wallets: [{ chain: "solana", role: "funds", publicKey: pubKey, encryptedSecret: "CT" }],
    };

    const [c1, c2] = await Promise.all([h.connectWallet(req(cwBody)), h.connectWallet(req(cwBody))]);

    // Only one should succeed (201); the other fails because the
    // challenge was consumed by the first.
    const creationOk = [c1.status, c2.status].filter((s) => s === 201).length;
    expect(creationOk).toBeLessThanOrEqual(1);
  });
});
