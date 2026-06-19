// End-to-end hardening tests for the high-level AuthClient (src/client/authClient.ts),
// the SDK's primary consumer entrypoint (previously ~17% covered). We wire global
// `fetch` straight to the real server handlers over a MemoryAdapter, so each test
// exercises the true client→HTTP→server→storage path — not a simulation.
//
// The node test env has no browser globals, so we polyfill the minimal window +
// localStorage that session.ts touches (setSession persists the token/email and arms
// the in-memory vault; authHeaders reads them back). securityLevel 1 (100k PBKDF2)
// keeps key derivation fast; the orchestration is identical at any level.
//
// Biometric flows (registerWithBiometric / { registration } / { biometricUnlock })
// need navigator.credentials and are covered by biometric-unlock.test.ts — out of
// scope here. This suite focuses on email + web3 + the reveal/unlock re-auth paths.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { AuthClient } from "../src/client/authClient";
import { createAuthHandlers, type AuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { getAppKey, lockVault } from "../src/client/session";
import type { EncryptedWallet } from "../src/core/types";

const EMAIL = "user@example.com";
const PASSKEY = "correct horse battery staple";
const WRONG_PASSKEY = "trustno1";

// --- minimal browser globals (window + localStorage) -------------------------
function makeStore() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
  };
}
function installBrowserGlobals() {
  const localStorage = makeStore();
  const noop = () => {};
  const g = global as unknown as Record<string, unknown>;
  g.localStorage = localStorage;
  g.window = {
    addEventListener: noop,
    removeEventListener: noop,
    dispatchEvent: () => true,
    location: { hostname: "localhost" },
  };
  g.document = { addEventListener: noop, removeEventListener: noop, visibilityState: "visible" };
  return localStorage;
}

// --- route global fetch to the in-process handlers ---------------------------
function wireFetch(h: AuthHandlers): void {
  const post: Record<string, (req: Request) => Promise<Response>> = {
    challenge: h.challenge,
    register: h.register,
    login: h.login,
    "login-wallet": h.loginWallet,
    "connect-wallet": h.connectWallet,
    "import-wallet": h.importWallet,
    logout: h.logout,
  };
  const get: Record<string, (req: Request) => Promise<Response>> = {
    "user-data": h.userData,
    "search-wallet": h.searchWallet,
  };
  (global as unknown as { fetch: typeof fetch }).fetch = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ) => {
    const raw = typeof input === "string" ? input : input.toString();
    const abs = raw.startsWith("http") ? raw : `http://localhost${raw}`;
    const path = new URL(abs).pathname.replace(/^\/api\/auth\//, "");
    const method = (init?.method ?? "GET").toUpperCase();
    const handler = method === "POST" ? post[path] : get[path];
    if (!handler) return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
    // Rebuild a clean Request (drop keepalive etc. that undici may reject).
    const req = new Request(abs, { method, headers: init?.headers, body: init?.body as BodyInit });
    return handler(req);
  }) as typeof fetch;
}

function newClient(): AuthClient {
  return new AuthClient({
    apiBaseUrl: "/api/auth",
    // appId fixed (avoids the default-"ttc" warn); level 1 = 100k PBKDF2 for speed;
    // big autoLock window so the idle timer never fires mid-test.
    config: { appId: "test-app", securityLevel: 1, autoLockMs: 60_000, lockOnHide: false },
    walletGen: { solana: ["funds", "signing"], evm: ["funds"] },
  });
}

function walletSigner() {
  const kp = Keypair.generate();
  return {
    publicKey: kp.publicKey.toBase58(),
    signMessage: async (m: Uint8Array) => nacl.sign.detached(m, kp.secretKey),
  };
}

let client: AuthClient;

beforeAll(() => installBrowserGlobals());
beforeEach(() => {
  (global as unknown as { localStorage: ReturnType<typeof makeStore> }).localStorage.clear();
  lockVault(); // reset the shared vault singleton between tests
  wireFetch(createAuthHandlers({ storage: new MemoryAdapter() }));
  client = newClient();
});
afterEach(() => lockVault()); // clears the pending auto-lock timer

describe("AuthClient — email/passkey", () => {
  it("registers, generates encrypted wallets, arms the vault, and persists session", async () => {
    const res = await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });

    expect(res.authToken).toHaveLength(64);
    expect(res.user.authMethod).toBe("email");
    expect(getAppKey()).not.toBeNull(); // vault armed after register

    // Wallets came back as ciphertext only — never plaintext key material.
    const sol = res.user.wallets.find((w) => w.chain === "solana" && w.role === "funds")!;
    const evm = res.user.wallets.find((w) => w.chain === "evm" && w.role === "funds")!;
    expect(sol.encryptedSecret).toMatch(/^[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$/); // iv:ct+tag (b64url)
    expect(evm.encryptedSecret).toContain(":");
    expect(JSON.stringify(res.user)).not.toContain("authToken"); // sanitized record
  });

  it("logs in by re-deriving the key and signing the challenge (deterministic recovery)", async () => {
    const reg = await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });
    lockVault();

    const login = await client.loginWithEmail({ email: EMAIL, passkey: PASSKEY });
    expect(login.publicKey).toBe(reg.publicKey); // same account
    expect(login.authToken).not.toBe(reg.authToken); // fresh token
    expect(getAppKey()).not.toBeNull(); // re-armed
  });

  it("rejects a wrong passkey (server returns 401 → client throws)", async () => {
    await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });
    await expect(client.loginWithEmail({ email: EMAIL, passkey: WRONG_PASSKEY })).rejects.toThrow(
      /invalid credentials/i,
    );
  });

  it("fetchUserData returns the record (token from the persisted session)", async () => {
    await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });
    const user = await client.fetchUserData();
    expect(user?.email).toBe(EMAIL);
    expect(user?.wallets.length).toBeGreaterThan(0);
  });
});

describe("AuthClient — web3 wallet", () => {
  it("connectWallet upserts a new wallet and arms the vault", async () => {
    const w = walletSigner();
    const res = await client.connectWallet(w);
    expect(res.publicKey).toBe(w.publicKey);
    expect(res.user.authMethod).toBe("wallet");
    expect(getAppKey()).not.toBeNull();
  });

  it("registerWithWallet stores a client-generated bundle under the signature-derived key", async () => {
    const w = walletSigner();
    const res = await client.registerWithWallet(w);
    expect(res.user.wallets.some((x) => x.chain === "solana")).toBe(true);
  });
});

describe("AuthClient — reveal/unlock re-auth guarantees", () => {
  async function registerAndGetSolanaFunds(): Promise<EncryptedWallet> {
    const res = await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });
    return res.user.wallets.find((w) => w.chain === "solana" && w.role === "funds")!;
  }

  it("revealSecret derives a one-time key and does NOT arm the session (re-auth to reveal)", async () => {
    const wallet = await registerAndGetSolanaFunds();
    lockVault();
    expect(getAppKey()).toBeNull();

    const secret = await client.revealSecret(wallet, { passkey: PASSKEY });
    expect(secret).toMatch(/^[0-9a-f]{128}$/); // 64-byte Solana secret key, hex
    expect(getAppKey()).toBeNull(); // STILL locked — revealing never widens the signing window
  });

  it("revealSecret with a wrong passkey fails closed", async () => {
    const wallet = await registerAndGetSolanaFunds();
    lockVault();
    await expect(client.revealSecret(wallet, { passkey: WRONG_PASSKEY })).rejects.toThrow(
      /re-authentication failed/i,
    );
  });

  it("revealSecret accepts a web3 { signMessage } re-auth", async () => {
    const w = walletSigner();
    const res = await client.registerWithWallet(w);
    const wallet = res.user.wallets.find((x) => x.chain === "solana")!;
    lockVault();
    const secret = await client.revealSecret(wallet, { signMessage: w.signMessage });
    expect(secret).toMatch(/^[0-9a-f]{128}$/);
  });

  it("unlock re-runs the ceremony, validates against a wallet, and arms the vault", async () => {
    const wallet = await registerAndGetSolanaFunds();
    lockVault();
    expect(getAppKey()).toBeNull();

    await client.unlock({ passkey: PASSKEY }, wallet);
    expect(getAppKey()).not.toBeNull(); // armed

    lockVault();
    // A wrong passkey fails the validating decrypt and does NOT arm.
    await expect(client.unlock({ passkey: WRONG_PASSKEY }, wallet)).rejects.toThrow(/wrong credentials/i);
    expect(getAppKey()).toBeNull();
  });
});

describe("AuthClient — logout", () => {
  it("revokes the session server-side and clears local state", async () => {
    await client.registerWithEmail({ email: EMAIL, passkey: PASSKEY });
    expect(getAppKey()).not.toBeNull();

    client.logout();
    expect(getAppKey()).toBeNull(); // vault dropped
    // Token is gone, so a subsequent user-data fetch is unauthorized → null.
    await expect(client.fetchUserData()).resolves.toBeNull();
  });
});
