#!/usr/bin/env node
// Verifies the Sign In With Solana wallet-login message end to end, against the BUILT
// dist/ (the published artifact). See PRD/siws-login-message-PRD.md §7–§8.
//
// Two modes:
//   In-process (default, no network): a fresh MemoryAdapter-backed server per origin.
//     npm run verify:siws
//   Live: a running deployment. Creates ONE throwaway wallet account (empty wallets) there.
//     node scripts/verify-siws-login.mjs --url http://localhost:3000/api/auth [--app-id <id>] [--origin <site>]
//     --origin defaults to the --url origin; set it when the auth API is served from a
//     different origin than the site (it must equal the server's config.origin).
//
// Checks, per origin:
//   message — the reference SIWS parser recovers every field and re-creates the bytes;
//             line 1 is the bare authority; printable ASCII + LF; fits a Ledger envelope.
//   wire    — a signature for this origin connects (201) and logs in (200); one for the
//             other scheme, another port, another site, or naming another address is
//             rejected (401), as is a replayed challenge; hostile Origin/X-Forwarded-Host
//             headers and a body `origin` change nothing.
//   boot    — (in-process only) createAuthHandlers rejects a malformed origin.
//
// Exit code 0 = all checks green; 1 = a check failed or dist/ is missing.

// ---------- tiny assert harness ----------
let failures = 0;
const check = (name, cond, detail = "") => {
  console.log(`  ${cond ? "✓" : "✗"} ${name}${!cond && detail ? ` — ${detail}` : ""}`);
  if (!cond) failures++;
};

// ---------- args ----------
const args = process.argv.slice(2);
const arg = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const LIVE_URL = arg("--url")?.replace(/\/+$/, "");
const APP_ID = arg("--app-id");
const LIVE_ORIGIN = arg("--origin") ?? (LIVE_URL ? new URL(LIVE_URL).origin : undefined);

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
const { walletLoginMessage, WALLET_LOGIN_STATEMENT, generateChallenge, offchainMessageCandidates } = core;

const { Keypair } = await import("@solana/web3.js");
const nacl = (await import("tweetnacl")).default;
const { parseSignInMessageText, createSignInMessageText } = await import("@solana/wallet-standard-util");

const enc = (s) => new TextEncoder().encode(s);
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/** The same origin with http and https swapped. */
const otherScheme = (origin) => {
  const u = new URL(origin);
  u.protocol = u.protocol === "https:" ? "http:" : "https:";
  return u.origin;
};
/** The same origin on a port it is not on. */
const otherPort = (origin) => {
  const u = new URL(origin);
  u.port = u.port === "8443" ? "9443" : "8443";
  return u.origin;
};

// ---------- message ----------
function checkMessage(origin) {
  const kp = Keypair.generate();
  const address = kp.publicKey.toBase58();
  const challenge = generateChallenge();
  const expected = new URL(origin);
  const m = walletLoginMessage({ challenge, origin, address });
  const bytes = enc(m);
  // parseSignInMessageText takes a STRING; the bytes variant would return null here.
  const p = parseSignInMessageText(m);

  check("reference parser accepts it", p !== null);
  check(`line 1 is the bare authority "${expected.host}"`, p?.domain === expected.host, p?.domain);
  check("line 2 is the signer's address", p?.address === address);
  check("statement is WALLET_LOGIN_STATEMENT", p?.statement === WALLET_LOGIN_STATEMENT);
  check(`URI keeps the scheme "${expected.origin}"`, p?.uri === expected.origin, p?.uri);
  check('Version is "1"', p?.version === "1");
  check("Nonce is the challenge", p?.nonce === challenge);
  check(
    "re-created byte-for-byte by createSignInMessageText",
    p !== null && createSignInMessageText(p) === m,
  );
  check(
    "printable ASCII + LF only",
    bytes.every((b) => b === 0x0a || (b >= 0x20 && b <= 0x7e)),
  );
  let envelopes = [];
  try {
    envelopes = offchainMessageCandidates(bytes, kp.publicKey.toBytes());
  } catch (e) {
    envelopes = [];
  }
  check(`fits a Ledger off-chain envelope (${bytes.length} ≤ 1212 bytes)`, envelopes.length > 0);
}

// ---------- wire ----------
async function checkWire(origin, post) {
  const kp = Keypair.generate();
  const W = kp.publicKey.toBase58();
  const sign = (text) => bytesToHex(nacl.sign.detached(enc(text), kp.secretKey));

  const ch = await post("challenge", { publicKey: W });
  const { challenge } = ch.body ?? {};
  check(
    "/challenge issues a SIWS-valid nonce",
    ch.status === 200 && /^[A-Za-z0-9]{8,}$/.test(challenge ?? ""),
  );
  if (!challenge) return;
  const connect = (signature, headers, extra = {}) =>
    post("connect-wallet", { publicKey: W, signature, challenge, wallets: [], ...extra }, headers);

  // Rejections first: verification runs before the challenge is consumed, so none of
  // these burn it. Six failures stay under the default 10/min per-key limit.
  const reject = async (name, text, headers, extra) => {
    const r = await connect(sign(text), headers, extra);
    check(`${name} → 401`, r.status === 401, `got ${r.status}`);
  };
  const bad = generateChallenge();
  await reject(
    `signed for ${otherScheme(origin)}`,
    walletLoginMessage({ challenge, origin: otherScheme(origin), address: W }),
  );
  await reject(
    `signed for ${otherPort(origin)}`,
    walletLoginMessage({ challenge, origin: otherPort(origin), address: W }),
  );
  await reject(
    "signed for another site, sent with that site's Origin/X-Forwarded-Host and body origin",
    walletLoginMessage({ challenge, origin: "https://evil.example", address: W }),
    { origin: "https://evil.example", "x-forwarded-host": "evil.example" },
    { origin: "https://evil.example" },
  );
  await reject(
    "line 2 names another address",
    walletLoginMessage({ challenge, origin, address: Keypair.generate().publicKey.toBase58() }),
  );
  await reject("signed over a different nonce", walletLoginMessage({ challenge: bad, origin, address: W }));

  const ok = await connect(sign(walletLoginMessage({ challenge, origin, address: W })), {
    origin: "https://evil.example",
    "x-forwarded-host": "evil.example",
  });
  check(
    "signed for this origin → 201 (hostile headers ignored)",
    ok.status === 201 && ok.body?.publicKey === W,
    `got ${ok.status}${ok.status === 401 ? " — is the server on ≥0.6.1 with config.origin = " + origin + "?" : ""}`,
  );
  const replay = await connect(sign(walletLoginMessage({ challenge, origin, address: W })));
  check("replayed challenge → 401", replay.status === 401, `got ${replay.status}`);

  const ch2 = await post("challenge", { publicKey: W });
  const login = await post("login-wallet", {
    publicKey: W,
    signature: sign(walletLoginMessage({ challenge: ch2.body?.challenge, origin, address: W })),
    challenge: ch2.body?.challenge,
  });
  check("login-wallet with a fresh challenge → 200", login.status === 200, `got ${login.status}`);
}

function inProcessPost(handlers) {
  const route = { challenge: "challenge", "connect-wallet": "connectWallet", "login-wallet": "loginWallet" };
  return async (path, body, headers = {}) => {
    const res = await handlers[route[path]](
      new Request(`http://localhost/api/auth/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
      }),
    );
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}

function livePost(baseUrl, appId) {
  return async (path, body, headers = {}) => {
    let res;
    try {
      res = await fetch(`${baseUrl}/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(appId ? { appId, ...body } : body),
      });
    } catch (e) {
      console.error(`\n✗ Could not reach ${baseUrl}/${path}: ${e.cause?.code ?? e.message}\n`);
      process.exit(1);
    }
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}

// ---------- run ----------
if (LIVE_URL) {
  console.log(`\nSIWS wallet-login verification — LIVE ${LIVE_URL} (site origin ${LIVE_ORIGIN})\n`);
  console.log("Message:");
  checkMessage(LIVE_ORIGIN);
  console.log("\nWire:");
  await checkWire(LIVE_ORIGIN, livePost(LIVE_URL, APP_ID));
} else {
  console.log("\nSIWS wallet-login verification — in-process against dist/\n");
  for (const origin of ["http://localhost:3000", "https://www.tetrac.xyz", "https://x.example:8443"]) {
    console.log(`${origin} — message:`);
    checkMessage(origin);
    console.log(`${origin} — wire:`);
    await checkWire(
      origin,
      inProcessPost(
        createAuthHandlers({ storage: new MemoryAdapter(), config: { origin }, onWarning: () => {} }),
      ),
    );
    console.log("");
  }
  console.log("Boot:");
  for (const origin of [
    "myapp.example",
    "https://myapp.example/app",
    "https://myapp.example?x=1",
    "capacitor://localhost",
  ]) {
    let threw = false;
    try {
      createAuthHandlers({ storage: new MemoryAdapter(), config: { origin }, onWarning: () => {} });
    } catch (e) {
      threw = /\[tetrac\] Invalid origin/.test(e.message);
    }
    check(`createAuthHandlers rejects ${JSON.stringify(origin)}`, threw);
  }
}

console.log(failures ? `\n✗ ${failures} check(s) failed\n` : "\n✓ all checks passed\n");
process.exit(failures ? 1 : 0);
