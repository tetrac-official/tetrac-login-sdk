// C-1 — Web3 wallet signatures are bound to the ORIGIN they were produced for.
//
// The attack this closes: `walletLoginMessage` used to be
// `"Sign this message to verify wallet ownership: <challenge>"` — a bare nonce naming
// no site, byte-identical across every deployment of this SDK. `/challenge` is
// unauthenticated and accepts any public key (a Solana address is public on-chain), so
// a phishing page could:
//
//   1. fetch a REAL challenge from victim.app for the victim's address,
//   2. prompt the victim to sign it (the prompt named no site, so nothing looked wrong),
//   3. relay that signature to victim.app/login-wallet and receive a live session, and
//   4. prompt for the app-key message too — which was bound only by `appId`, a value the
//      CLIENT chooses — then take SHA-256 of the signature to obtain the victim's real
//      app key and decrypt their entire wallet bundle.
//
// Both signatures were genuine, so every downstream check (ed25519 verify, single-use
// challenge, TTL) passed correctly. Only the missing origin binding made it work.
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

describe("C-1 — wallet login signatures are origin-bound", () => {
  it("🚨 a signature harvested on ANOTHER origin does NOT verify", () => {
    const kp = Keypair.generate();
    const challenge = "ab".repeat(32);

    // The victim really did sign — but on evil.app, so the message names evil.app.
    const harvested = sign(kp, enc(walletLoginMessage(challenge, EVIL_ORIGIN)));

    // victim.app verifies against ITS OWN origin. The preimages differ, so it fails.
    expect(verifySolanaSignature(kp.publicKey.toBase58(), harvested, challenge, VICTIM_ORIGIN)).toBe(false);

    // Sanity: the same signature is valid for the origin it was actually made for, so
    // the rejection above is the binding working — not a broken signature.
    expect(verifySolanaSignature(kp.publicKey.toBase58(), harvested, challenge, EVIL_ORIGIN)).toBe(true);
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
    const relayed = sign(kp, enc(walletLoginMessage(challenge, EVIL_ORIGIN)));
    const res = await h.loginWallet(jreq({ appId: APP_ID, publicKey, signature: relayed, challenge }));
    expect(res.status).toBe(401);

    // The honest signature for this deployment still works — same challenge, so this
    // also proves the failed attempt did not burn it.
    const honest = sign(kp, enc(walletLoginMessage(challenge, VICTIM_ORIGIN)));
    const ok = await h.connectWallet(
      jreq({ appId: APP_ID, publicKey, signature: honest, challenge, wallets: [] }),
    );
    expect(ok.status).toBe(201);
  });

  it("🚨 the APP-KEY message is origin-bound too — a hostile appId no longer reproduces the key", () => {
    const kp = Keypair.generate();

    // The attacker sets appId to the victim deployment's. That alone used to be enough,
    // because appId is chosen by the client.
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
    const challenge = "cd".repeat(32);
    const sig = sign(kp, enc(walletLoginMessage(challenge, VICTIM_ORIGIN)));

    for (const variant of ["https://victim.app/", "HTTPS://VICTIM.APP", "  https://victim.app  "]) {
      expect(normalizeOrigin(variant)).toBe(VICTIM_ORIGIN);
      expect(verifySolanaSignature(kp.publicKey.toBase58(), sig, challenge, variant)).toBe(true);
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
