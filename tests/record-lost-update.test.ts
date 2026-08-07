// H-1 (audit.md) — concurrent writes to one user record must not destroy wallet keys.
//
// The record used to be a single JSON blob, and EVERY write rewrote it wholesale:
// `issueSession` called `persistUser` on every login purely to store `authTokenHash`, and
// `importWallet` concatenated an array and wrote the whole thing back. Two overlapping
// requests each wrote their own stale snapshot and the later one won outright.
//
// That is not a lost UI update. `encryptedSecret` is the ONLY copy of a client-generated
// private key — the plaintext existed in the browser for the duration of
// generateWalletBundle() and was never persisted anywhere. Losing the ciphertext is
// unrecoverable by design: no backup, no escrow, no re-derivation. Assets already sent to
// that address are stranded permanently. Both requests returned 200.
//
// The fix is structural, not a retry: the record is stored one field per slot (a hash
// field on KV, a row on SQL), so a login writes only the session pointer and an import
// writes only its own slot. They cannot collide, so there is no conflict to detect.
import { Keypair } from "@solana/web3.js";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { KvAuthStore } from "../src/storage/store";
import { registerEmail, loginEmail, jreq, addressFor } from "./_auth-helpers";

const APP_KEY = "ab".repeat(32);
const ORIGIN = "https://test.example";

const slot = (chain: "solana" | "evm", role: "funds" | "signing", secret: string) => ({
  chain,
  role,
  publicKey: `pk-${chain}-${role}`,
  encryptedSecret: secret,
});

function handlers(storage: MemoryAdapter) {
  return createAuthHandlers({ storage, config: { origin: ORIGIN } });
}

async function newAccount(storage: MemoryAdapter, email: string) {
  const h = handlers(storage);
  const idLabel = Keypair.generate().publicKey.toBase58();
  const publicKey = addressFor(idLabel);
  const res = await registerEmail(h, {
    publicKey: idLabel,
    email,
    appKey: APP_KEY,
    wallets: [slot("solana", "funds", "original-solana")],
  });
  expect(res.status).toBe(201);
  const body = await res.json();
  return { h, publicKey, authToken: body.authToken as string };
}

const authHeaders = (token: string, publicKey: string) => ({
  "ttc-auth-token": token,
  "ttc-public-key": publicKey,
});

describe("H-1 — a concurrent login cannot destroy an imported wallet", () => {
  it("🚨 import + login in flight together: BOTH survive", async () => {
    const storage = new MemoryAdapter();
    const email = "race@example.com";
    const { h, publicKey, authToken } = await newAccount(storage, email);

    // The exact reproduction from the audit: an import overlapping a re-login.
    await Promise.all([
      h.importWallet(
        jreq({ wallets: [slot("evm", "funds", "imported-evm")] }, authHeaders(authToken, publicKey)),
      ),
      loginEmail(h, { email, appKey: APP_KEY }),
    ]);

    const store = new KvAuthStore(storage);
    const user = await store.getUser("ttc", publicKey);
    const secrets = (user?.wallets ?? []).map((w) => w.encryptedSecret).sort();

    expect(secrets).toEqual(["imported-evm", "original-solana"]);
  });

  it("🚨 two concurrent imports of DIFFERENT slots: neither is lost", async () => {
    const storage = new MemoryAdapter();
    const { h, publicKey, authToken } = await newAccount(storage, "two@example.com");
    const auth = authHeaders(authToken, publicKey);

    await Promise.all([
      h.importWallet(jreq({ wallets: [slot("evm", "funds", "ct-A")] }, auth)),
      h.importWallet(jreq({ wallets: [slot("evm", "signing", "ct-B")] }, auth)),
    ]);

    const user = await new KvAuthStore(storage).getUser("ttc", publicKey);
    const secrets = (user?.wallets ?? []).map((w) => w.encryptedSecret).sort();
    expect(secrets).toEqual(["ct-A", "ct-B", "original-solana"]);
  });

  it("two concurrent imports of the SAME slot resolve last-write-wins, not corruption", async () => {
    const storage = new MemoryAdapter();
    const { h, publicKey, authToken } = await newAccount(storage, "same@example.com");
    const auth = authHeaders(authToken, publicKey);

    await Promise.all([
      h.importWallet(jreq({ wallets: [slot("evm", "funds", "ct-A")] }, auth)),
      h.importWallet(jreq({ wallets: [slot("evm", "funds", "ct-B")] }, auth)),
    ]);

    const user = await new KvAuthStore(storage).getUser("ttc", publicKey);
    const evmFunds = user?.wallets.filter((w) => w.chain === "evm" && w.role === "funds") ?? [];
    // Exactly one entry — one of the two, never both and never neither. That is the
    // correct meaning of "replace this slot".
    expect(evmFunds).toHaveLength(1);
    expect(["ct-A", "ct-B"]).toContain(evmFunds[0]!.encryptedSecret);
    expect(user?.wallets).toHaveLength(2); // the untouched solana slot is intact
  });

  it("a login writes ONLY the session pointer — the profile and wallet fields are untouched", async () => {
    const storage = new MemoryAdapter();
    const email = "pointer@example.com";
    const { publicKey, h } = await newAccount(storage, email);

    const before = await storage.hgetall(`pubKey:ttc:${publicKey}`);
    await loginEmail(h, { email, appKey: APP_KEY });
    const after = await storage.hgetall(`pubKey:ttc:${publicKey}`);

    // Only the session-pointer field `t` may differ.
    for (const field of Object.keys(before)) {
      if (field === "t") continue;
      expect(after[field]).toBe(before[field]);
    }
    expect(after.t).not.toBe(before.t);
  });
});
