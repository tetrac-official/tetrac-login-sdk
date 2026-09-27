// M-4 (audit.md) — a Ledger firmware update must not make a user's wallets undecryptable.
//
// A Web3 app key is SHA-256(signature) over a FIXED message. For a hardware wallet that
// signature is produced over a Solana off-chain ENVELOPE, and which envelope the device
// accepts is a property of its FIRMWARE — discovered at signing time by a cascade that
// tries `legacy` (20-byte header) and falls back to `v0` (85-byte) on 0x6a81.
//
// Nothing recorded the choice. So a firmware update that flips the accepted layout made the
// same wallet, signing the same message, produce a DIFFERENT signature — a different app
// key — and every stored wallet failed to decrypt. Login still SUCCEEDED, because the
// server accepts either envelope for the challenge signature, so the user authenticated
// normally and then found their funds unreachable. There is no recovery path: the
// ciphertext is the only copy of those private keys.
//
// The layout is now pinned on the account at registration and returned by /challenge.
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { deriveAppKeyFromSignature } from "../src/core/crypto";
import {
  walletAppKeyMessageHw,
  walletLoginMessage,
  encodeOffchainMessageAs,
  type OffchainEnvelope,
} from "../src/core/index";
import { jreq } from "./_auth-helpers";

const ORIGIN = "https://test.example";
const APP_ID = "ttc";

const handlers = (storage: MemoryAdapter) => createAuthHandlers({ storage, config: { origin: ORIGIN } });

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** A Ledger whose firmware accepts exactly one envelope layout. */
function device(kp: Keypair, firmware: OffchainEnvelope) {
  return {
    /** Mirrors createLedgerSolanaSigner: pin when told, else cascade and report. */
    signMessage(
      message: Uint8Array,
      opts: { envelope?: OffchainEnvelope; onEnvelope?: (e: OffchainEnvelope) => void } = {},
    ): Uint8Array {
      if (opts.envelope) {
        if (opts.envelope !== firmware) throw new Error("Ledger error: 0x6a81");
        return nacl.sign.detached(
          encodeOffchainMessageAs(opts.envelope, message, kp.publicKey.toBytes()),
          kp.secretKey,
        );
      }
      for (const candidate of ["legacy", "v0"] as const) {
        if (candidate !== firmware) continue; // the device rejects the others with 0x6a81
        opts.onEnvelope?.(candidate);
        return nacl.sign.detached(
          encodeOffchainMessageAs(candidate, message, kp.publicKey.toBytes()),
          kp.secretKey,
        );
      }
      throw new Error("Ledger rejected every known off-chain message format (0x6a81).");
    },
  };
}

const appKeyFor = (kp: Keypair, firmware: OffchainEnvelope, pinned?: OffchainEnvelope) =>
  deriveAppKeyFromSignature(
    toHex(
      device(kp, firmware).signMessage(
        new TextEncoder().encode(walletAppKeyMessageHw(APP_ID, ORIGIN)),
        pinned ? { envelope: pinned } : {},
      ),
    ),
  );

describe("M-4 — the off-chain envelope is app-key derivation input", () => {
  it("🚨 the two layouts derive DIFFERENT app keys from the same wallet and message", () => {
    const kp = Keypair.generate();
    // This is the whole hazard in one assertion: the device's firmware silently selects
    // which of these the user gets.
    expect(appKeyFor(kp, "legacy")).not.toBe(appKeyFor(kp, "v0"));
  });

  it("🚨 pinning survives a firmware flip — the key is unchanged", () => {
    const kp = Keypair.generate();
    const atRegistration = appKeyFor(kp, "legacy"); // cascade picks legacy, and we record it

    // The user updates their Ledger and the device now speaks v0. Cascading would give a
    // different key; pinning refuses instead — loudly, not silently.
    expect(() => appKeyFor(kp, "v0", "legacy")).toThrow(/0x6a81/);

    // …and a device still on the registered firmware derives the SAME key as day one.
    expect(appKeyFor(kp, "legacy", "legacy")).toBe(atRegistration);
  });

  it("without pinning, a firmware flip silently yields a different key", () => {
    // The pre-fix behaviour, kept as a witness: no error, no signal — just a wrong key.
    const kp = Keypair.generate();
    expect(appKeyFor(kp, "v0")).not.toBe(appKeyFor(kp, "legacy"));
  });
});

describe("M-4 — the server pins and returns the envelope", () => {
  async function registerHardware(
    h: ReturnType<typeof createAuthHandlers>,
    kp: Keypair,
    envelope: OffchainEnvelope,
  ) {
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(jreq({ publicKey }))).json();
    // The AUTH signature may cascade freely — it is challenge-bound and stateless.
    const sig = toHex(
      nacl.sign.detached(
        encodeOffchainMessageAs(
          envelope,
          new TextEncoder().encode(walletLoginMessage({ challenge, origin: ORIGIN, address: publicKey })),
          kp.publicKey.toBytes(),
        ),
        kp.secretKey,
      ),
    );
    return h.register(
      jreq({
        publicKey,
        authMethod: "wallet",
        wallets: [],
        signature: sig,
        challenge,
        offchainEnvelope: envelope,
      }),
    );
  }

  it.each(["legacy", "v0"] as const)(
    "🚨 /challenge returns the pinned %s envelope so the client never cascades again",
    async (envelope) => {
      const storage = new MemoryAdapter();
      const h = handlers(storage);
      const kp = Keypair.generate();

      expect((await registerHardware(h, kp, envelope)).status).toBe(201);

      const body = await (await h.challenge(jreq({ publicKey: kp.publicKey.toBase58() }))).json();
      expect(body.offchainEnvelope).toBe(envelope);
    },
  );

  it("a software wallet gets no envelope — it signs raw bytes and has nothing to pin", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();

    const { challenge } = await (await h.challenge(jreq({ publicKey }))).json();
    const sig = toHex(
      nacl.sign.detached(
        new TextEncoder().encode(walletLoginMessage({ challenge, origin: ORIGIN, address: publicKey })),
        kp.secretKey,
      ),
    );
    expect((await h.connectWallet(jreq({ publicKey, signature: sig, challenge, wallets: [] }))).status).toBe(
      201,
    );

    const body = await (await h.challenge(jreq({ publicKey }))).json();
    expect(body.offchainEnvelope).toBeUndefined();
  });

  it("rejects an envelope value outside the known layouts", async () => {
    const storage = new MemoryAdapter();
    const h = handlers(storage);
    const kp = Keypair.generate();
    const publicKey = kp.publicKey.toBase58();
    const { challenge } = await (await h.challenge(jreq({ publicKey }))).json();

    const res = await h.register(
      jreq({
        publicKey,
        authMethod: "wallet",
        wallets: [],
        signature: "00".repeat(64),
        challenge,
        offchainEnvelope: "v99",
      }),
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("Invalid offchainEnvelope");
  });
});
