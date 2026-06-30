// Ledger Solana signer + off-chain envelope — pure-module correctness, no device.
//
// The "device" here is a real ed25519 keypair: the mock signs exactly the bytes
// it is handed. That lets us cryptographically VERIFY (via tweetnacl) that the
// signer serialized the correct preimage and reattached the signature under the
// right key — for legacy txs, versioned (v0) txs, and off-chain messages.
import nacl from "tweetnacl";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  encodeOffchainMessage,
  encodeOffchainMessageLegacy,
  offchainMessageCandidates,
} from "../src/core/offchainMessage";
import { createLedgerSolanaSigner } from "../src/ledger/solanaSigner";
import { mapLedgerDeviceError } from "../src/ledger/transport";

const PATH = "m/44'/501'/0'/0'";
// PublicKey.default.toBase58() is a valid 32-byte base58 — fine as a stand-in blockhash.
const BLOCKHASH = PublicKey.default.toBase58();

function makeSigner(kp: Keypair, opts: { wrongSigLen?: boolean } = {}) {
  // Records what the device was asked to sign so tests can assert the preimage.
  const calls: { tx: Uint8Array[]; msg: Uint8Array[] } = { tx: [], msg: [] };
  const sign = (bytes: Uint8Array): Uint8Array => {
    const sig = nacl.sign.detached(bytes, kp.secretKey);
    return opts.wrongSigLen ? sig.slice(0, 63) : sig;
  };
  const signer = createLedgerSolanaSigner({
    address: kp.publicKey.toBase58(),
    path: PATH,
    signTransaction: async (_path, message) => {
      calls.tx.push(message);
      return sign(message);
    },
    signOffchainMessage: async (_path, envelope) => {
      calls.msg.push(envelope);
      return sign(envelope);
    },
  });
  return { signer, calls };
}

describe("createLedgerSolanaSigner", () => {
  it("exposes the account public key", () => {
    const kp = Keypair.generate();
    const { signer } = makeSigner(kp);
    expect(signer.publicKey.toBase58()).toBe(kp.publicKey.toBase58());
  });

  it("signs a legacy Transaction over serializeMessage() and reattaches verifiably", async () => {
    const kp = Keypair.generate();
    const { signer, calls } = makeSigner(kp);

    const tx = new Transaction();
    tx.feePayer = kp.publicKey;
    tx.recentBlockhash = BLOCKHASH;
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 1 }));

    const signed = await signer.signTransaction(tx);

    // The device was handed exactly serializeMessage()'s bytes.
    expect(Buffer.from(calls.tx[0]!)).toEqual(Buffer.from(signed.serializeMessage()));
    // The reattached signature verifies against the message under the account key.
    const sig = signed.signature!;
    expect(sig).not.toBeNull();
    expect(
      nacl.sign.detached.verify(signed.serializeMessage(), new Uint8Array(sig), kp.publicKey.toBytes()),
    ).toBe(true);
    // web3.js agrees the signature is valid.
    expect(signed.verifySignatures()).toBe(true);
  });

  it("signs a VersionedTransaction over message.serialize() (incl. 0x80 prefix) and reattaches verifiably", async () => {
    const kp = Keypair.generate();
    const { signer, calls } = makeSigner(kp);

    const message = new TransactionMessage({
      payerKey: kp.publicKey,
      recentBlockhash: BLOCKHASH,
      instructions: [
        SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 1 }),
      ],
    }).compileToV0Message();
    const vtx = new VersionedTransaction(message);

    const signed = await signer.signTransaction(vtx);

    const preimage = signed.message.serialize();
    expect(preimage[0]! & 0x80).toBe(0x80); // v0 prefix present in what we signed
    expect(Buffer.from(calls.tx[0]!)).toEqual(Buffer.from(preimage));
    expect(nacl.sign.detached.verify(preimage, signed.signatures[0]!, kp.publicKey.toBytes())).toBe(true);
  });

  it("signAllTransactions signs each transaction (one device call apiece)", async () => {
    const kp = Keypair.generate();
    const { signer, calls } = makeSigner(kp);

    const mk = () => {
      const tx = new Transaction();
      tx.feePayer = kp.publicKey;
      tx.recentBlockhash = BLOCKHASH;
      tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 1 }));
      return tx;
    };
    const signed = await signer.signAllTransactions([mk(), mk()]);
    expect(signed).toHaveLength(2);
    expect(calls.tx).toHaveLength(2);
    for (const tx of signed) expect(tx.verifySignatures()).toBe(true);
  });

  it("signMessage signs the first accepted off-chain envelope (legacy) verifiably", async () => {
    const kp = Keypair.generate();
    const { signer, calls } = makeSigner(kp);

    const msg = new TextEncoder().encode("Sign in to Tetrac\nnonce: 12345");
    const sig = await signer.signMessage(msg);

    // The mock device accepts the first candidate (legacy, 20-byte header).
    const legacy = encodeOffchainMessageLegacy(msg);
    expect(Buffer.from(calls.msg[0]!)).toEqual(Buffer.from(legacy));
    expect(nacl.sign.detached.verify(legacy, sig, kp.publicKey.toBytes())).toBe(true);
  });

  it("signMessage cascades to v0 when the device rejects the legacy header (0x6a81)", async () => {
    const kp = Keypair.generate();
    const msg = new TextEncoder().encode("login challenge");
    const legacy = encodeOffchainMessageLegacy(msg);
    const v0 = encodeOffchainMessage(msg, kp.publicKey.toBytes());
    const seenLengths: number[] = [];

    // Firmware that only supports v0: rejects the legacy header with 0x6a81.
    const signer = createLedgerSolanaSigner({
      address: kp.publicKey.toBase58(),
      path: PATH,
      signTransaction: async () => new Uint8Array(64),
      signOffchainMessage: async (_path, envelope) => {
        seenLengths.push(envelope.length);
        if (envelope.length === legacy.length) {
          throw new Error("Ledger device: UNKNOWN_ERROR (0x6a81)");
        }
        return nacl.sign.detached(envelope, kp.secretKey);
      },
    });

    const sig = await signer.signMessage(msg);
    expect(seenLengths).toEqual([legacy.length, v0.length]); // tried legacy, then v0
    expect(nacl.sign.detached.verify(v0, sig, kp.publicKey.toBytes())).toBe(true);
  });

  it("signMessage surfaces a non-0x6a81 device error immediately (no silent fallback)", async () => {
    const kp = Keypair.generate();
    const signer = createLedgerSolanaSigner({
      address: kp.publicKey.toBase58(),
      path: PATH,
      signTransaction: async () => new Uint8Array(64),
      signOffchainMessage: async () => {
        throw new Error("Transaction was rejected on the Ledger device.");
      },
    });
    await expect(signer.signMessage(new TextEncoder().encode("hi"))).rejects.toThrow(/rejected/);
  });

  it("rejects a non-64-byte device signature (fail-closed)", async () => {
    const kp = Keypair.generate();
    const { signer } = makeSigner(kp, { wrongSigLen: true });
    const tx = new Transaction();
    tx.feePayer = kp.publicKey;
    tx.recentBlockhash = BLOCKHASH;
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 1 }));
    await expect(signer.signTransaction(tx)).rejects.toThrow(/expected 64/);
  });
});

describe("encodeOffchainMessage", () => {
  const pk = new Uint8Array(32).fill(9);

  it("lays out the legacy 20-byte envelope (no app domain, no signers)", () => {
    const env = encodeOffchainMessageLegacy("Hi");
    expect(env.length).toBe(20 + 2);
    expect(env[0]).toBe(0xff);
    expect(Buffer.from(env.slice(1, 16)).toString("ascii")).toBe("solana offchain");
    expect(env[16]).toBe(0x00); // version
    expect(env[17]).toBe(0x00); // format = RestrictedAscii
    expect(env[18]).toBe(2); // length u16 LE low
    expect(env[19]).toBe(0); // length u16 LE high
    expect(Buffer.from(env.slice(20)).toString("ascii")).toBe("Hi");
  });

  it("offchainMessageCandidates returns [legacy, v0] in cascade order", () => {
    const cands = offchainMessageCandidates("Hi", pk);
    expect(cands).toHaveLength(2);
    expect(Buffer.from(cands[0]!)).toEqual(Buffer.from(encodeOffchainMessageLegacy("Hi")));
    expect(Buffer.from(cands[1]!)).toEqual(Buffer.from(encodeOffchainMessage("Hi", pk)));
  });

  it("lays out the V0 single-signer envelope exactly per the Ledger firmware parser", () => {
    const env = encodeOffchainMessage("Hi", pk);
    expect(env.length).toBe(85 + 2); // 85-byte header + 2-byte message

    expect(env[0]).toBe(0xff);
    expect(Buffer.from(env.slice(1, 16)).toString("ascii")).toBe("solana offchain");
    expect(env[16]).toBe(0x00); // header version v0
    expect(env.slice(17, 49).every((b) => b === 0)).toBe(true); // app domain zeros
    expect(env[49]).toBe(0x00); // format = RestrictedAscii
    expect(env[50]).toBe(0x01); // signer count
    expect(Buffer.from(env.slice(51, 83))).toEqual(Buffer.from(pk)); // signer pubkey
    expect(env[83]).toBe(2); // length u16 LE low byte
    expect(env[84]).toBe(0); // length u16 LE high byte
    expect(Buffer.from(env.slice(85)).toString("ascii")).toBe("Hi");
  });

  it("accepts a Uint8Array message and a custom 32-byte application domain", () => {
    const domain = new Uint8Array(32).fill(7);
    const env = encodeOffchainMessage(new TextEncoder().encode("ok"), pk, { applicationDomain: domain });
    expect(env.slice(17, 49).every((b) => b === 7)).toBe(true);
  });

  it("rejects empty messages, oversized messages, and bad pubkey lengths", () => {
    expect(() => encodeOffchainMessage("", pk)).toThrow(/non-empty/);
    expect(() => encodeOffchainMessage("x".repeat(1213), pk)).toThrow(/exceeds/);
    expect(() => encodeOffchainMessage("hi", new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => encodeOffchainMessage("hi", pk, { applicationDomain: new Uint8Array(16) })).toThrow(
      /32 bytes/,
    );
  });

  it("rejects non-ASCII by default but allows UTF-8 with format=1 when opted in", () => {
    const emoji = "gm \u{1F319}"; // contains a non-ASCII codepoint
    expect(() => encodeOffchainMessage(emoji, pk)).toThrow(/ASCII/);
    const env = encodeOffchainMessage(emoji, pk, { allowUtf8: true });
    expect(env[49]).toBe(0x01); // format = LimitedUtf8
  });
});

describe("mapLedgerDeviceError", () => {
  const cases: Array<[string, RegExp]> = [
    ["Ledger device: UNKNOWN_ERROR (0x6e01)", /open the Solana app/],
    ["Ledger device: Locked device (0x5515)", /unlock/],
    ["Transaction approval request was rejected (0x6985)", /rejected on the Ledger device/i],
    ["Missing a parameter. Try enabling blind signature in the app", /Blind Signing/i],
    ["DisconnectedDeviceDuringOperation: Failed to execute", /disconnected/i],
  ];
  it.each(cases)("maps %s", (msg, re) => {
    expect(mapLedgerDeviceError(new Error(msg), "Transaction")).toMatch(re);
  });

  it("passes through an unrecognized message unchanged", () => {
    expect(mapLedgerDeviceError(new Error("something novel"), "Op")).toBe("something novel");
  });
});
