#!/usr/bin/env node
// Standalone smoke test for multi-app Upstash isolation (v0.4.0) — runs against the
// BUILT dist/ (the published artifact), with NO jest and NO network. One MemoryAdapter
// stands in for one shared Redis/Upstash DB; two appIds share it and must stay isolated.
//
// Run:  npm run smoke:multiapp        (builds dist/ first, then runs this)
//   or: npm run build && node scripts/smoke-multi-app.mjs
//
// Exit code 0 = all checks green; 1 = a check failed or dist/ is missing.

// ---------- tiny assert harness ----------
let failures = 0;
const check = (name, cond) => {
  console.log(`  ${cond ? "✓" : "✗"} ${name}`);
  if (!cond) failures++;
};

// ---------- import the BUILT artifacts ----------
let server, storage, core;
try {
  server = await import(new URL("../dist/server/index.js", import.meta.url).href);
  storage = await import(new URL("../dist/storage/index.js", import.meta.url).href);
  core = await import(new URL("../dist/core/index.js", import.meta.url).href);
} catch (e) {
  console.error("✗ Could not import dist/ — run `npm run build` first.\n", e);
  process.exit(1);
}
const { createAuthHandlers } = server;
const { MemoryAdapter } = storage;
const { walletLoginMessage } = core;

const { Keypair } = await import("@solana/web3.js");
const nacl = (await import("tweetnacl")).default;

const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const req = (body, headers = {}) =>
  new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const APP_A = "app.alpha";
const APP_B = "app.beta";
const PK_A = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const PK_B = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";

console.log(
  "\nmulti-app isolation smoke test — against dist/, one shared MemoryAdapter (= one Upstash DB)\n",
);

// One shared DB + one shared auth service, serving multiple apps.
const db = new MemoryAdapter();
const h = createAuthHandlers({ storage: db });

// 1) Email index is a { appId: publicKey } map — the requested shape.
console.log("Email index → { appId: publicKey } map:");
const EMAIL = "shared@example.com";
const emailReg = (appId, publicKey) =>
  h.register(
    req({ appId, publicKey, email: EMAIL, authMethod: "email", authPublicKey: "11".repeat(32), wallets: [] }),
  );
check("register email on app A → 201", (await emailReg(APP_A, PK_A)).status === 201);
check("register SAME email on app B → 201 (no false 409)", (await emailReg(APP_B, PK_B)).status === 201);
const map = await db.hgetall(`email:${EMAIL}`);
check(
  `email:${EMAIL} == { ${APP_A}: ${PK_A.slice(0, 6)}…, ${APP_B}: ${PK_B.slice(0, 6)}… }`,
  map[APP_A] === PK_A && map[APP_B] === PK_B,
);
check(
  "records live under disjoint app-scoped keys",
  (await db.get(`pubKey:${APP_A}:${PK_A}`)) !== null && (await db.get(`pubKey:${APP_B}:${PK_A}`)) === null,
);

// 2) Same wallet on two apps → independent records, each its own encrypted bundle.
console.log("\nSame wallet, two apps — independent encrypted bundles:");
const kp = Keypair.generate();
const W = kp.publicKey.toBase58();
async function connect(appId, ct) {
  const { challenge } = await (await h.challenge(req({ appId, publicKey: W }))).json();
  const sig = bytesToHex(
    nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(challenge)), kp.secretKey),
  );
  const wallets = [{ chain: "solana", role: "funds", publicKey: W, encryptedSecret: ct }];
  return h.connectWallet(req({ appId, publicKey: W, signature: sig, challenge, wallets }));
}
const ca = await connect(APP_A, "CT_A");
const cb = await connect(APP_B, "CT_B");
check("connect wallet on app A → 201 (new)", ca.status === 201);
check("connect SAME wallet on app B → 201 (new, not a returning app-A user)", cb.status === 201);
const bundleA = (await ca.json()).user.wallets[0].encryptedSecret;
const bundleB = (await cb.json()).user.wallets[0].encryptedSecret;
check(
  "app A keeps CT_A; app B keeps CT_B (no cross-app bundle bleed)",
  bundleA === "CT_A" && bundleB === "CT_B",
);

// 3) A challenge issued for one app does not satisfy another.
console.log("\nChallenge scoping:");
const { challenge: chA } = await (await h.challenge(req({ appId: APP_A, publicKey: W }))).json();
const sigA = bytesToHex(nacl.sign.detached(new TextEncoder().encode(walletLoginMessage(chA)), kp.secretKey));
const cross = await h.loginWallet(req({ appId: APP_B, publicKey: W, signature: sigA, challenge: chA }));
check("app-A challenge spent under app B → 401", cross.status === 401);

// 4) A session minted by one app is rejected by another.
console.log("\nSession scoping:");
const SESS_PK = "EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1";
const reg = await h.register(
  req({
    appId: APP_A,
    publicKey: SESS_PK,
    email: "sess@example.com",
    authMethod: "email",
    authPublicKey: "11".repeat(32),
    wallets: [],
  }),
);
const { authToken, publicKey } = await reg.json();
const sameApp = await h.userData(
  req({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey, "ttc-app-id": APP_A }),
);
const crossApp = await h.userData(
  req({}, { "ttc-auth-token": authToken, "ttc-public-key": publicKey, "ttc-app-id": APP_B }),
);
check("token used under its own app → 200", sameApp.status === 200);
check("same token used under another app → 401", crossApp.status === 401);

// 5) appId validation.
console.log("\nappId validation:");
const colon = await h.register(
  req({
    appId: "a:b",
    publicKey: PK_A,
    email: "x@y.com",
    authMethod: "email",
    authPublicKey: "11".repeat(32),
    wallets: [],
  }),
);
check("appId containing ':' (namespace separator) → 400", colon.status === 400);
const allow = createAuthHandlers({ storage: new MemoryAdapter(), config: { allowedAppIds: [APP_A] } });
const undeclared = await allow.register(
  req({
    appId: APP_B,
    publicKey: PK_B,
    email: "x@y.com",
    authMethod: "email",
    authPublicKey: "11".repeat(32),
    wallets: [],
  }),
);
check("undeclared appId with allowedAppIds set → 400", undeclared.status === 400);

console.log("");
if (failures) {
  console.error(`SMOKE FAILED — ${failures} check(s) failed.`);
  process.exit(1);
}
console.log("SMOKE PASSED — all checks green.");
process.exit(0);
