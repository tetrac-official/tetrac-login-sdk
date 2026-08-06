// Shared helpers for the signature-auth flow.
// Not a *.test.ts file, so jest won't run it as a suite — it's imported by suites.
//
// These SIMULATE THE REAL CLIENT. Where they diverge from `AuthClient`, every suite that
// uses them is exercising a state real accounts never reach — which is worse than no
// coverage, because it reads as coverage. Keep them in step with
// `src/client/authClient.ts`.
import { deriveAuthPublicKey, signAuthChallenge } from "../src/client/authKey";
import { PBKDF2_ITERATIONS, DEFAULT_CONFIG } from "../src/core/config";

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
export function registerEmail(
  h: Handlers,
  opts: {
    email: string;
    appKey: string;
    publicKey: string;
    wallets?: unknown[];
    /** `null` omits it entirely (the legacy/wallet shape); undefined takes the default. */
    pbkdf2Iterations?: number | null;
    appId?: string;
  },
): Promise<Response> {
  const iterations =
    opts.pbkdf2Iterations === null
      ? undefined
      : (opts.pbkdf2Iterations ?? PBKDF2_ITERATIONS[DEFAULT_CONFIG.securityLevel]);
  return h.register(
    jreq({
      appId: opts.appId,
      publicKey: opts.publicKey,
      email: opts.email,
      authPublicKey: deriveAuthPublicKey(opts.appKey),
      authMethod: "email",
      wallets: opts.wallets ?? [],
      pbkdf2Iterations: iterations,
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
