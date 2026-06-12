// Shared helpers for the signature-auth flow (v0.2.1 Change 3).
// Not a *.test.ts file, so jest won't run it as a suite — it's imported by suites.
// Simulates the client: register stores the derived auth public key; login fetches
// a challenge and signs it with the auth keypair derived from the appKey.
import { deriveAuthPublicKey, signAuthChallenge } from "../src/client/authKey";

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

/** Register an email account the new way (stores authPublicKey, never a passkey hash). */
export function registerEmail(
  h: Handlers,
  opts: { email: string; appKey: string; publicKey: string; wallets?: unknown[]; pbkdf2Iterations?: number },
): Promise<Response> {
  return h.register(
    jreq({
      publicKey: opts.publicKey,
      email: opts.email,
      authPublicKey: deriveAuthPublicKey(opts.appKey),
      authMethod: "email",
      wallets: opts.wallets ?? [],
      pbkdf2Iterations: opts.pbkdf2Iterations,
    }),
  );
}

/** Log in an email account: challenge -> sign with the auth keypair -> login. */
export async function loginEmail(h: Handlers, opts: { email: string; appKey: string }): Promise<Response> {
  const ch = (await (await h.challenge(jreq({ email: opts.email }))).json()) as { challenge: string };
  const signature = signAuthChallenge(opts.appKey, ch.challenge);
  return h.login(jreq({ email: opts.email, signature, challenge: ch.challenge }));
}
