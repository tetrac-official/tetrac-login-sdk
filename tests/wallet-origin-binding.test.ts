// C-1 — Web3 wallet signatures are bound to the ORIGIN they were produced for.
//
// `walletLoginMessage` is a Sign In With Solana message. It names the site twice — the bare
// host on line 1 ("victim.app wants you to sign in with your Solana account:") and the full
// origin, scheme and port included, on the `URI:` line — and carries the signer's address
// and the single-use challenge as its nonce. The server rebuilds it from its OWN
// config.origin and the public key it verifies under, never from anything in the request.
//
// The attack this closes: `/challenge` is unauthenticated and accepts any public key (a
// Solana address is public on-chain), so without the origin binding a phishing page could:
//
//   1. fetch a REAL challenge from victim.app for the victim's address,
//   2. prompt the victim to sign it,
//   3. relay that signature to victim.app/login-wallet and receive a live session, and
//   4. prompt for the app-key message too — otherwise bound only by `appId`, a value the
//      CLIENT chooses — then take SHA-256 of the signature to obtain the victim's real
//      app key and decrypt their entire wallet bundle.
//
// Both signatures are genuine, so every downstream check (ed25519 verify, single-use
// challenge, TTL) passes. Only the binding stops it: a signature made on evil.app names
// evil.app, and verifies nowhere else — not on another scheme or port, and not under
// another address.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { verifySolanaSignature } from "../src/server/signature";
import {
  walletLoginMessage,
  walletAppKeyMessage,
  walletAppKeyMessageHw,
  normalizeOrigin,
} from "../src/core/index";
import { deriveAppKeyFromSignature } from "../src/core/crypto";
import { jreq } from "./_auth-helpers";

const VICTIM_ORIGIN = "https://victim.app";
const EVIL_ORIGIN = "https://evil.app";
const APP_ID = "victim-app";

const enc = (s: string) => new TextEncoder().encode(s);
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sign = (kp: Keypair, msg: Uint8Array) => toHex(nacl.sign.detached(msg, kp.secretKey));

/** A request in which everything that could name a site names evil.app. */
const fromEvil = (body: Record<string, unknown>) =>
  new Request(`${EVIL_ORIGIN}/api/auth`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: EVIL_ORIGIN,
      host: "evil.app",
      "x-forwarded-host": "evil.app",
    },
    body: JSON.stringify({ ...body, origin: EVIL_ORIGIN }),
  });

describe("C-1 — wallet login signatures are origin-bound", () => {
  it("🚨 a signature harvested on ANOTHER origin does NOT verify", () => {
    const kp = Keypair.generate();
    const address = kp.publicKey.toBase58();
    const challenge = "ab".repeat(32);

    // The victim really did sign — but on evil.app, so the message names evil.app.
    const harvested = sign(kp, enc(walletLoginMessage({ challenge, origin: EVIL_ORIGIN, address })));

    // victim.app verifies against ITS OWN origin. The preimages differ, so it fails.
    expect(verifySolanaSignature(address, harvested, challenge, VICTIM_ORIGIN)).toBe(false);

    // Sanity: the same signature is valid for the origin it was actually made for, so
    // the rejection above is the binding working — not a broken signature.
    expect(verifySolanaSignature(address, harvested, challenge, EVIL_ORIGIN)).toBe(true);
  });

  it("🚨 the relayed signature is rejected end-to-end by /login-wallet", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { appId: APP_ID, origin: VICTIM_ORIGIN } });
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    // Step 1: the attacker's backend obtains a genuine challenge from the victim app.
    const chRes = await h.challenge(jreq({ appId: APP_ID, publicKey }));
    const { challenge } = await chRes.json();
    expect(typeof challenge).toBe("string");

    // Step 2-3: the victim signs on evil.app; the attacker relays it.
    const relayed = sign(kp, enc(walletLoginMessage({ challenge, origin: EVIL_ORIGIN, address: publicKey })));
    const res = await h.loginWallet(jreq({ appId: APP_ID, publicKey, signature: relayed, challenge }));
    expect(res.status).toBe(401);

    // The honest signature for this deployment still works — same challenge, so this
    // also proves the failed attempt did not burn it.
    const honest = sign(
      kp,
      enc(walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address: publicKey })),
    );
    const ok = await h.connectWallet(
      jreq({ appId: APP_ID, publicKey, signature: honest, challenge, wallets: [] }),
    );
    expect(ok.status).toBe(201);
  });

  it("🚨 http and https are different origins — the scheme is in the signed bytes", async () => {
    const HTTP_VICTIM = "http://victim.app";
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { appId: APP_ID, origin: VICTIM_ORIGIN } });
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(jreq({ appId: APP_ID, publicKey }))).json();

    // Line 1 carries only the host, the same for both schemes; the URI: line tells them apart.
    const overHttp = walletLoginMessage({ challenge, origin: HTTP_VICTIM, address: publicKey });
    const overHttps = walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address: publicKey });
    expect(overHttp.split("\n")[0]).toBe(overHttps.split("\n")[0]);
    expect(overHttp).not.toBe(overHttps);

    const sig = sign(kp, enc(overHttp));
    expect(verifySolanaSignature(publicKey, sig, challenge, VICTIM_ORIGIN)).toBe(false);
    // Sanity: valid on the origin it was made for, so the rejection is the scheme binding.
    expect(verifySolanaSignature(publicKey, sig, challenge, HTTP_VICTIM)).toBe(true);

    const res = await h.loginWallet(jreq({ appId: APP_ID, publicKey, signature: sig, challenge }));
    expect(res.status).toBe(401);
  });

  it("🚨 a different port is a different origin", () => {
    const ALT_PORT = "https://victim.app:8443";
    const kp = Keypair.generate();
    const address = kp.publicKey.toBase58();
    const challenge = "ef".repeat(32);
    const sig = sign(kp, enc(walletLoginMessage({ challenge, origin: ALT_PORT, address })));

    expect(verifySolanaSignature(address, sig, challenge, VICTIM_ORIGIN)).toBe(false);
    expect(verifySolanaSignature(address, sig, challenge, ALT_PORT)).toBe(true);
  });

  it("🚨 the server never takes its origin from the request — URL, headers and body are ignored", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { appId: APP_ID, origin: VICTIM_ORIGIN } });
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(jreq({ appId: APP_ID, publicKey }))).json();

    // A relayed evil.app signature, in a request that agrees it is from evil.app, is still
    // checked against victim.app's configured origin.
    const relayed = sign(kp, enc(walletLoginMessage({ challenge, origin: EVIL_ORIGIN, address: publicKey })));
    const attack = fromEvil({ appId: APP_ID, publicKey, signature: relayed, challenge, wallets: [] });
    expect(attack.headers.get("host")).toBe("evil.app"); // the hostile headers really are sent
    expect((await h.connectWallet(attack)).status).toBe(401);

    // The other direction: the honest victim.app signature in the SAME hostile request
    // succeeds, so nothing in the request is consulted at all.
    const honest = sign(
      kp,
      enc(walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address: publicKey })),
    );
    const ok = await h.connectWallet(
      fromEvil({ appId: APP_ID, publicKey, signature: honest, challenge, wallets: [] }),
    );
    expect(ok.status).toBe(201);
  });

  it("🚨 /login-wallet ignores the request's origin too", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { appId: APP_ID, origin: VICTIM_ORIGIN } });
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const signFor = (challenge: string, origin: string) =>
      sign(kp, enc(walletLoginMessage({ challenge, origin, address: publicKey })));
    const fresh = async () =>
      (await (await h.challenge(jreq({ appId: APP_ID, publicKey }))).json()).challenge as string;

    // An account to log in to.
    const first = await fresh();
    const created = await h.connectWallet(
      jreq({
        appId: APP_ID,
        publicKey,
        signature: signFor(first, VICTIM_ORIGIN),
        challenge: first,
        wallets: [],
      }),
    );
    expect(created.status).toBe(201);

    const challenge = await fresh();
    const attack = fromEvil({
      appId: APP_ID,
      publicKey,
      signature: signFor(challenge, EVIL_ORIGIN),
      challenge,
    });
    expect((await h.loginWallet(attack)).status).toBe(401);
    // Same challenge, same hostile request: the honest signature logs in, so the failed
    // attempt did not burn it and nothing in the request was consulted.
    const honest = fromEvil({
      appId: APP_ID,
      publicKey,
      signature: signFor(challenge, VICTIM_ORIGIN),
      challenge,
    });
    expect((await h.loginWallet(honest)).status).toBe(200);
  });

  it("🚨 /register ignores the request's origin too", async () => {
    const storage = new MemoryAdapter();
    const h = createAuthHandlers({ storage, config: { appId: APP_ID, origin: VICTIM_ORIGIN } });
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(jreq({ appId: APP_ID, publicKey }))).json();
    const register = (origin: string) =>
      h.register(
        fromEvil({
          appId: APP_ID,
          publicKey,
          authMethod: "wallet",
          signature: sign(kp, enc(walletLoginMessage({ challenge, origin, address: publicKey }))),
          challenge,
          wallets: [],
        }),
      );

    expect((await register(EVIL_ORIGIN)).status).toBe(401);
    expect((await register(VICTIM_ORIGIN)).status).toBe(201);
  });

  it("🚨 the APP-KEY message is origin-bound too — a hostile appId does not reproduce the key", () => {
    const kp = Keypair.generate();

    // The attacker sets appId to the victim deployment's, which it can: appId is chosen by
    // the client.
    const onEvil = deriveAppKeyFromSignature(sign(kp, enc(walletAppKeyMessage(APP_ID, EVIL_ORIGIN))));
    const onVictim = deriveAppKeyFromSignature(sign(kp, enc(walletAppKeyMessage(APP_ID, VICTIM_ORIGIN))));

    // Same wallet, same appId, different site -> different key. The harvested signature
    // decrypts nothing belonging to victim.app.
    expect(onEvil).not.toBe(onVictim);
  });

  it("stays deterministic for a given (appId, origin) — recovery must keep working", () => {
    const kp = Keypair.generate();
    const a = deriveAppKeyFromSignature(sign(kp, enc(walletAppKeyMessage(APP_ID, VICTIM_ORIGIN))));
    const b = deriveAppKeyFromSignature(sign(kp, enc(walletAppKeyMessage(APP_ID, VICTIM_ORIGIN))));
    expect(a).toBe(b);
  });

  it("normalizes origin casing and trailing slashes on both sides", () => {
    const kp = Keypair.generate();
    const address = kp.publicKey.toBase58();
    const challenge = "cd".repeat(32);
    const sig = sign(kp, enc(walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address })));

    for (const variant of ["https://victim.app/", "HTTPS://VICTIM.APP", "  https://victim.app  "]) {
      expect(normalizeOrigin(variant)).toBe(VICTIM_ORIGIN);
      expect(verifySolanaSignature(address, sig, challenge, variant)).toBe(true);
    }
  });

  it("the hardware (newline-free) app-key message is origin-bound and Ledger-clear-signable", () => {
    const msg = walletAppKeyMessageHw(APP_ID, VICTIM_ORIGIN);
    expect(msg).toContain(VICTIM_ORIGIN);
    expect(msg).not.toContain("\n"); // a newline forces Blind Signing / 0x6a82
    // Printable ASCII only, so the device renders it.
    expect(/^[\x20-\x7e]+$/.test(msg)).toBe(true);
    expect(walletAppKeyMessageHw(APP_ID, EVIL_ORIGIN)).not.toBe(msg);
  });
});

describe("C-1 — wallet login signatures are address-bound", () => {
  it("🚨 key B's signature over a message naming address A does not verify for B", () => {
    const addressA = Keypair.generate().publicKey.toBase58();
    const kpB = Keypair.generate();
    const addressB = kpB.publicKey.toBase58();
    const challenge = "34".repeat(32);

    const namingA = sign(
      kpB,
      enc(walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address: addressA })),
    );
    expect(verifySolanaSignature(addressB, namingA, challenge, VICTIM_ORIGIN)).toBe(false);

    // Control: same key, challenge and origin, naming itself — so the rejection above is the
    // address line alone.
    const namingB = sign(
      kpB,
      enc(walletLoginMessage({ challenge, origin: VICTIM_ORIGIN, address: addressB })),
    );
    expect(verifySolanaSignature(addressB, namingB, challenge, VICTIM_ORIGIN)).toBe(true);
  });
});

describe("C-1 — an origin-less deployment cannot exist", () => {
  it("🚨 createAuthHandlers REFUSES to build without config.origin", () => {
    // Stricter than failing at request time: there is no way to stand up a server that
    // would verify a signature bound to nothing. On a server there is nothing safe to
    // infer an origin FROM — the request's Host header is attacker-influenced, and
    // defaulting to it would hand the attacker the binding.
    expect(() => createAuthHandlers({ storage: new MemoryAdapter(), config: { appId: APP_ID } })).toThrow(
      /config\.origin is required/,
    );
  });

  it("resolveConfig throws outside a browser when no origin is supplied", async () => {
    const { resolveConfig } = await import("../src/core/config");
    expect(() => resolveConfig({ appId: APP_ID })).toThrow(/config\.origin is required/);
    expect(resolveConfig({ appId: APP_ID, origin: "HTTPS://Victim.App/" }).origin).toBe(VICTIM_ORIGIN);
  });
});

describe("C-1 — a server origin no login message can be built from is refused at boot", () => {
  const build = (origin: string) =>
    createAuthHandlers({ storage: new MemoryAdapter(), config: { appId: APP_ID, origin } });

  it.each([
    "myapp.example",
    "localhost:3000",
    "https://myapp.example/app",
    "https://myapp.example?x=1",
    "https://myapp.example#",
    "https://u:p@myapp.example",
    "capacitor://localhost",
    "ws://myapp.example",
  ])("🚨 createAuthHandlers REFUSES to build with config.origin %j", (origin) => {
    // Every wallet signature is verified against a message built from config.origin, and
    // none can be built from these (see parseOrigin). Accepting one would fail every wallet
    // login and registration with no error anywhere.
    expect(() => build(origin)).toThrow(/\[tetrac\] Invalid origin/);
  });

  it.each([
    "https://myapp.example",
    "HTTPS://MyApp.Example/",
    "http://localhost:3000",
    "https://myapp.example:8443",
  ])("builds with config.origin %j", (origin) => {
    expect(() => build(origin)).not.toThrow();
  });
});
