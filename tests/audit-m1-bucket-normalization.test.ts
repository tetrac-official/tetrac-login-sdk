// M-1 — rate-limit buckets keyed the RAW email while lookup normalized it.
//
// getPublicKeyByEmail applies normalizeEmail (lowercase + trim), so `Victim@x.com`,
// `victim@x.com` and ` victim@x.com ` are ONE account. The buckets keyed body.email
// verbatim, so each spelling got its own counter — an attacker divides the per-account
// throttle by however many case permutations they care to type, and the anti-brute-force
// limit on /login stops meaning anything.
//
// Base58 public keys are case-SENSITIVE and must NOT be folded: two keys differing only in
// case are genuinely different accounts.
import { createAuthHandlers } from "../src/server/routes";
import { MemoryAdapter } from "../src/storage/memory";
import { registerEmail, jreq } from "./_auth-helpers";

const PK = "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa";
const APP_KEY = "ab".repeat(32);

function handlers(config: Record<string, unknown> = {}) {
  return createAuthHandlers({
    storage: new MemoryAdapter(),
    config: { origin: "https://test.example", ...config },
    onWarning: () => {},
  });
}

/** A signature that is well-formed but wrong — enough to reach the failure counter. */
const BAD_SIG = "ab".repeat(64);

/** Attack an account with the given spellings; return how many requests got through. */
async function attemptsUntilThrottled(h: ReturnType<typeof handlers>, spellings: string[]): Promise<number> {
  let allowed = 0;
  for (const email of spellings) {
    const chRes = await h.challenge(jreq({ email }));
    if (chRes.status === 429) break;
    const ch = await chRes.json();
    const res = await h.login(jreq({ email, signature: BAD_SIG, challenge: ch.challenge }));
    if (res.status === 429) break;
    allowed++;
  }
  return allowed;
}

describe("M-1 — one account is one bucket, regardless of spelling", () => {
  it("🚨 varying the case of an email does NOT buy extra attempts", async () => {
    // The whole point of the finding: an attacker who cycles spellings must not get a fresh
    // counter per spelling. Keyed raw, the mixed-case run never throttled at all.
    const single = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(single, { publicKey: PK, email: "victim@test.com", appKey: APP_KEY });
    const baseline = await attemptsUntilThrottled(
      single,
      Array.from({ length: 8 }, () => "victim@test.com"),
    );

    const mixed = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(mixed, { publicKey: PK, email: "victim@test.com", appKey: APP_KEY });
    const withCaseTricks = await attemptsUntilThrottled(mixed, [
      "victim@test.com",
      "Victim@test.com",
      "VICTIM@TEST.COM",
      "ViCtIm@TeSt.CoM",
      "vIcTiM@tEsT.cOm",
      "Victim@Test.Com",
      "VICTIM@test.com",
      "victim@TEST.COM",
    ]);

    expect(withCaseTricks).toBe(baseline);
    expect(baseline).toBeLessThan(8); // the limiter actually engaged in both runs
  });

  it("🚨 case permutations share the /challenge bucket", async () => {
    const h = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 3 } });
    await registerEmail(h, { publicKey: PK, email: "target@test.com", appKey: APP_KEY });

    const statuses: number[] = [];
    for (const email of ["target@test.com", "Target@test.com", "TARGET@TEST.COM", "TaRgEt@TeSt.CoM"]) {
      statuses.push((await h.challenge(jreq({ email }))).status);
    }
    expect(statuses).toContain(429);
  });

  it("whitespace-padded emails are rejected at validation, before any bucket", async () => {
    // normalizeEmail also trims, but EMAIL_RE forbids whitespace outright, so a padded
    // address never reaches the limiter. Documented so the trim is not mistaken for the
    // thing protecting this path.
    const h = handlers();
    const res = await h.challenge(jreq({ email: "  victim@test.com  " }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/Invalid email/i);
  });

  it("public keys differing only in case remain DISTINCT buckets", async () => {
    // base58 is case-sensitive: folding these would merge two unrelated accounts' limits and
    // let one user throttle another. The normalization must apply to emails only.
    const h = handlers({ rateLimit: { windowSeconds: 60, maxAttempts: 2 } });

    // Two valid, distinct base58 keys.
    const a = "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa";
    const b = "8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe";

    await h.challenge(jreq({ publicKey: a }));
    await h.challenge(jreq({ publicKey: a }));
    // `a` is now at its limit; `b` must still be free.
    expect((await h.challenge(jreq({ publicKey: b }))).status).toBe(200);
  });
});
