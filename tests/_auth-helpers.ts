// Shared helpers for the signature-auth flow.
// Not a *.test.ts file, so jest won't run it as a suite — it's imported by suites.
//
// These SIMULATE THE REAL CLIENT. Where they diverge from `AuthClient`, every suite that
// uses them is exercising a state real accounts never reach — which is worse than no
// coverage, because it reads as coverage. Keep them in step with
// `src/client/authClient.ts`.
import { deriveAuthPublicKey, signAuthChallenge } from "../src/client/authKey";
import { PBKDF2_ITERATIONS, DEFAULT_CONFIG } from "../src/core/config";
import { walletLoginMessage } from "../src/core/index";
import { Keypair } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";
import nacl from "tweetnacl";

/**
 * Registration now requires PROOF OF POSSESSION of the identity key, so a test can no
 * longer name an arbitrary base58 string as its identity — that is exactly the pattern the
 * check forbids (H-5(2): planting a record at an address you do not control).
 *
 * Rather than rewrite ~79 call sites, the label a test passes as `publicKey` is used as a
 * SEED for a real keypair. Deterministic, so distinct labels stay distinct accounts and the
 * same label is the same account across calls — but the helper now actually holds the
 * private key, which is what makes it a faithful stand-in for the real client.
 *
 * Assertions that compare against the registered address must go through `addressFor()`.
 */
const identityCache = new Map<string, Keypair>();
/** Reverse index, so identityFor(addressFor(x)) === identityFor(x). */
const byAddress = new Map<string, Keypair>();

export function identityFor(label: string): Keypair {
  // IDEMPOTENT: a test may hold onto `addressFor(label)` and pass that back in. Without
  // this it would seed a second, different keypair and the address would silently change.
  const known = byAddress.get(label);
  if (known) return known;

  let kp = identityCache.get(label);
  if (!kp) {
    kp = Keypair.fromSeed(sha256(utf8ToBytes(`ttc-test-identity:${label}`)));
    identityCache.set(label, kp);
    byAddress.set(kp.publicKey.toBase58(), kp);
  }
  return kp;
}

/** The on-the-wire identity address a given label registers as. */
export function addressFor(label: string): string {
  return identityFor(label).publicKey.toBase58();
}

/**
 * Produce the possession proof `/register` now requires: fetch a challenge for `address`
 * and sign the login message naming `address` with `signer`. Pass a mismatched signer to
 * exercise the rejection path — the message still names the claimed `address`, so it
 * fails only on the key.
 */
export async function proofFor(
  h: { challenge: (req: Request) => Promise<Response> },
  signer: Keypair,
  opts: { address?: string; appId?: string; origin?: string } = {},
): Promise<{ signature: string; challenge: string }> {
  const address = opts.address ?? signer.publicKey.toBase58();
  const ch = (await (await h.challenge(jreq({ appId: opts.appId, publicKey: address }))).json()) as {
    challenge: string;
  };
  const msg = new TextEncoder().encode(
    walletLoginMessage({ challenge: ch.challenge, origin: opts.origin ?? "https://test.example", address }),
  );
  return { signature: bytesToHex(nacl.sign.detached(msg, signer.secretKey)), challenge: ch.challenge };
}

type Handler = (req: Request) => Promise<Response>;
interface Handlers {
  register: Handler;
  login: Handler;
  challenge: Handler;
}

export function jreq(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/**
 * Register an email account the way the real client does (stores authPublicKey, never a
 * passkey hash).
 *
 * `pbkdf2Iterations` DEFAULTS to the SDK's own default level, because `registerWithEmail`
 * always pins a count — an email account with none is a state the client cannot produce.
 * Leaving it unset here meant every test account was unpinned, which quietly hid a
 * /challenge response-shape difference between real and unknown accounts. Pass
 * `pbkdf2Iterations: null` to deliberately exercise the unpinned path.
 */
export async function registerEmail(
  h: Handlers,
  opts: {
    email: string;
    appKey: string;
    /** A LABEL, not a literal address — see identityFor(). Use addressFor() to assert. */
    publicKey: string;
    wallets?: unknown[];
    /** `null` omits it entirely (the legacy/wallet shape); undefined takes the default. */
    pbkdf2Iterations?: number | null;
    appId?: string;
    /** Skip the possession proof, to exercise the server's rejection of an unproven key. */
    omitProof?: boolean;
    /** Sign with a DIFFERENT key than the one claimed — the squatting attempt. */
    signAs?: Keypair;
    origin?: string;
  },
): Promise<Response> {
  const iterations =
    opts.pbkdf2Iterations === null
      ? undefined
      : (opts.pbkdf2Iterations ?? PBKDF2_ITERATIONS[DEFAULT_CONFIG.securityLevel]);

  const identity = identityFor(opts.publicKey);
  const address = identity.publicKey.toBase58();

  // Mirror the real client: fetch a challenge for the identity key, then sign it with that
  // key. The server verifies and consumes it before creating the record.
  let proof: { signature: string; challenge: string } | Record<string, never> = {};
  if (!opts.omitProof) {
    const ch = (await (await h.challenge(jreq({ appId: opts.appId, publicKey: address }))).json()) as {
      challenge: string;
    };
    const signer = opts.signAs ?? identity;
    // The message names the claimed `address` even under `signAs`, so a mismatched signer
    // fails only on the key.
    const msg = new TextEncoder().encode(
      walletLoginMessage({ challenge: ch.challenge, origin: opts.origin ?? "https://test.example", address }),
    );
    proof = { signature: bytesToHex(nacl.sign.detached(msg, signer.secretKey)), challenge: ch.challenge };
  }

  return h.register(
    jreq({
      appId: opts.appId,
      publicKey: address,
      email: opts.email,
      authPublicKey: deriveAuthPublicKey(opts.appKey),
      authMethod: "email",
      wallets: opts.wallets ?? [],
      pbkdf2Iterations: iterations,
      ...proof,
    }),
  );
}

/**
 * Log in an email account: challenge -> sign with the auth keypair -> login.
 *
 * NOTE: `/challenge` answers 200 for an UNKNOWN email too, with an unstored dummy — the
 * 400 it used to return was an account-existence oracle. So this helper reaching `login`
 * proves nothing about the account existing; assert on the LOGIN response, never on the
 * challenge step.
 */
export async function loginEmail(
  h: Handlers,
  opts: { email: string; appKey: string; appId?: string },
): Promise<Response> {
  const ch = (await (await h.challenge(jreq({ appId: opts.appId, email: opts.email }))).json()) as {
    challenge: string;
  };
  const signature = signAuthChallenge(opts.appKey, ch.challenge);
  return h.login(jreq({ appId: opts.appId, email: opts.email, signature, challenge: ch.challenge }));
}
