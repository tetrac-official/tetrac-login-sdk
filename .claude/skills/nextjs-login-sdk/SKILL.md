---
name: nextjs-login-sdk
description: Upgrade a Next.js / React app from `@tetrac/login-sdk` 0.5.0 to 0.6.0. Covers the two changes that DESTROY DATA if you skip them — the required `config.origin`, and the origin-bound wallet app-key message that makes every Web3 account's encrypted wallets undecryptable — plus removed config fields (`sessionHeader`/`publicKeyHeader`/`appIdHeader`, `webauthn.preferPrf`), the deleted WebAuthn gate mode, the changed `AuthStore` contract (`takeChallenge` signature, new `putWalletSlot`/`setSessionPointer`), `/challenge` no longer 404-ing unknown emails, and the new SQL backends. Use when — upgrading the SDK version in a consuming app; seeing "config.origin is required" thrown at boot; a Web3 user reporting "my wallets stopped decrypting" or "wrong app key" after an upgrade; `PrfUnavailableError` where biometric used to work; a custom AuthStore failing to compile; TypeScript errors on `walletLoginMessage`/`walletAppKeyMessage` arity; or `sessionHeader is not assignable`. Triggers — "upgrade login-sdk", "migrate to 0.7", "0.5.0 to 0.6", "bump tetrac sdk", "config.origin is required", "wallets stopped decrypting after upgrade", "preferPrf does not exist", "takeChallenge signature changed".
---

# Upgrading `@tetrac/login-sdk` 0.5.0 → 0.6.0

## 🛑 Read this before running `npm install`

Two changes in this range are **destructive**, and neither announces itself as one. Both are silent:
the app boots, logins succeed, and the damage only surfaces when a user tries to spend.

1. **Every Web3 (wallet) account loses access to its encrypted wallets.** The app-key message is now
   origin-bound, so the same wallet signing the same prompt derives a **different key**. The
   ciphertext is unchanged and unreadable. There is no re-derivation path and no backup — that
   ciphertext is the only copy of the private key.
2. **Every biometric account registered in gate mode is dead.** Gate mode was deleted. Those
   credentials have no PRF output to re-derive from.

Email + passkey accounts are **unaffected** — their salt is `SHA-256(appId:email)`, which never
involved the origin. If the app is email-only, this upgrade is routine. Read § *Step 0* to find out
which population you actually have before touching anything.

## Version map

`0.5.0` → `0.6.0` (SQL backends, origin binding, hash-shaped records) → `0.6.0` (session/enumeration
hardening). There is no separate 0.6 → 0.7 upgrade path worth documenting; go straight to 0.6.0.

---

## Step 0 — Find out what you're dealing with

Run this against your production store **before** upgrading. The answer decides whether this is a
30-minute job or a user-comms project.

```ts
// Count accounts by authMethod. Web3 and gate-mode-biometric are the at-risk populations.
// Adapt the scan to your backend — this is the Redis-family shape.
const keys = await redis.keys("pubKey:*");
const byMethod: Record<string, number> = {};
for (const k of keys) {
  const rec = await redis.hget(k, "p");          // the profile field
  const m = JSON.parse(rec ?? "{}").authMethod ?? "email";
  byMethod[m] = (byMethod[m] ?? 0) + 1;
}
console.log(byMethod);   // { email: 812, wallet: 47, biometric: 9 }
```

| `authMethod` | Impact | What you must do |
|---|---|---|
| `email` | **None.** Salt is `SHA-256(appId:email)` — no origin, no change. | Nothing. |
| `wallet` | **Wallets become undecryptable.** App key was `SHA-256(sig)` over a message that just gained `Site: {origin}`. | § *Step 2*. Requires user action — there is no server-side fix. |
| `biometric` (PRF) | None — PRF output never involved the origin. | Nothing. |
| `biometric` (gate) | **Dead.** Gate mode deleted in 0.6.0. | User re-registers. You cannot tell gate from PRF in the record — see § *Step 3*. |

**If `wallet` is 0 and `biometric` is 0, skip to § Step 4.** Most email-only apps are in this bucket.

---

## Step 1 — `config.origin` is now required (this is why it throws at boot)

`resolveConfig` **throws** without it. In a browser it defaults to `window.location.origin`; on a
server there is no default, deliberately — a wallet signature that verifies against nothing in
particular is worse than a boot failure.

```ts
// app/api/auth/[...action]/route.ts
export const { GET, POST } = createNextAuthRoutes({
  storage,
  config: {
    appId: APP_ID,
    origin: "https://myapp.example",   // ← NEW, REQUIRED. Scheme + host (+ port).
                                       //   No path, no trailing slash.
  },
});
```

It is **app-key derivation input for Web3 accounts**. Treat it exactly like `appId`: set it once,
never change it. Changing it later re-derives every wallet-account key and strands those wallets —
the same failure this upgrade causes once.

Per-environment values are a trap. A preview deployment on `https://myapp-git-xyz.vercel.app` derives
different keys than production. Either pin the production origin everywhere, or accept that preview
deployments are throwaway accounts only:

```ts
origin: process.env.NEXT_PUBLIC_SITE_ORIGIN ?? "https://myapp.example",
```

The server compares against **its own** configured origin, never the request's — echoing a
client-supplied origin back into the message reinstates the relay attack the binding exists to stop.

---

## Step 2 — The Web3 wallet break (no automated fix exists)

### What changed

```ts
// 0.5.0
walletAppKeyMessage(appId)            → "…\n\nApp: myapp"
walletLoginMessage(challenge)         → "Sign this message to verify wallet ownership: <hex>"

// 0.6.0
walletAppKeyMessage(appId, origin)    → "…\n\nApp: myapp\nSite: https://myapp.example"
walletLoginMessage(challenge, origin) → "https://myapp.example wants you to sign in with your
                                         Solana account.\n\nURI: …\nNonce: <hex>"
```

The app key is `SHA-256(hex(signature))` over that message. Different message → different signature →
different app key → `decryptSecret` throws on every wallet in the record.

**Login still works.** That is the cruel part. `walletLoginMessage` is challenge-bound and stateless,
so authentication succeeds normally — the user signs in, sees their account, and finds their wallets
unreadable. Expect the bug report to be "my funds are gone", not "decryption failed".

### Your three options

There is no code that fixes this. Pick one and communicate it.

**(a) Have users export before you upgrade.** The only option that preserves keys. Ship a reveal flow
on 0.5.0, tell wallet users to export, then upgrade. Slow, but nothing is lost.

```tsx
// On 0.5.0, BEFORE upgrading — useExportKey forces a fresh re-auth ceremony.
const { reveal } = useExportKey(solanaFunds);
const secret = await reveal({ signMessage });   // user imports this into Phantom etc.
```

**(b) Accept the loss for empty wallets.** If your Web3 accounts hold no assets (common when
`connectWallet` users sign in with Phantom and never fund the embedded wallet), the stranded
ciphertext is worthless. Verify balances on-chain first — do not assume.

**(c) Stay on 0.5.0 for Web3, upgrade email-only.** Not really viable; the two paths share one
server. Mentioned only to be dismissed.

### If you already upgraded

Roll the SDK back to 0.5.0, restore the previous `origin`-free message, and run option (a). The
ciphertext is intact — only the derivation input changed. Nothing is lost **until** a user deletes
their account or you sweep the records.

---

## Step 3 — WebAuthn gate mode is gone

0.5.0 fell back to "gate mode" when an authenticator lacked PRF: a random secret encrypted under a
non-extractable `CryptoKey` in IndexedDB. That was removed because non-extractability protects the
key *bytes*, not the *decryption capability* — `CryptoKey` round-trips through IndexedDB with its
usages intact, so any same-origin script could decrypt the secret with no WebAuthn assertion at all.

0.6.0 requires PRF and **fails closed**:

```ts
import { PrfUnavailableError } from "@tetrac/login-sdk/client";

try {
  await registerWithBiometric({ userName });
} catch (e) {
  if (e instanceof PrfUnavailableError) {
    // Authenticator has no PRF. Offer email+passkey instead — do NOT silently downgrade.
  }
}
```

Removed: `gateDelete()`, `webauthn.preferPrf` (PRF is not a preference any more).

**You cannot distinguish gate from PRF accounts in the stored record** — the distinction lived
entirely in the browser's IndexedDB. Treat every biometric account as possibly-gate: catch
`PrfUnavailableError` on login and route those users to re-register. In practice gate mode only ever
triggered on authenticators without PRF (older Windows Hello, some cross-platform keys); Touch ID and
Face ID have always had it.

---

## Step 4 — Removed and changed config

```ts
// ❌ REMOVED — these no longer exist on AuthConfig
sessionHeader: "x-my-token",
publicKeyHeader: "x-my-pubkey",
appIdHeader: "x-my-app",
webauthn: { preferPrf: true },
```

The three header names are now shared constants, exported from `@tetrac/login-sdk/core`:

```ts
import { AUTH_TOKEN_HEADER, PUBLIC_KEY_HEADER, APP_ID_HEADER } from "@tetrac/login-sdk/core";
```

They were removed rather than fixed because they never worked: the server honoured the config while
the client hardcoded the literals, so any deployment that set them 401'd on every authenticated
request. If you set them on 0.5.0, your app was already broken in a way you may have worked around —
check for a manual header shim and delete it.

### New

| Field | Default | Why you may want to set it |
|---|---|---|
| `origin` | *(required)* | § Step 1 |
| `accountCreationRateLimit` | `{ windowSeconds: 60, maxAttempts: 2 }` | Deployment-wide ceiling on **new accounts**, not on logins. Raise it if you expect legitimate signup bursts; it is global and has no key to rotate. |
| `allowedAppIds` | *(unset)* | Now warns at boot when unset. Set it to the ids you actually serve. |

### Changed defaults

- `sessionTtlSeconds`: `14400` (4h) → `86400` (24h).
- Unknown route action: `404` → `400` (configurable via `unknownActionStatus`).

### New boot warnings

0.6.0 warns on `console.warn` at `createAuthHandlers` time for `unrestricted_app_id`,
`default_app_id`, and `no_requester_identity`. Route them into your logger instead of stderr:

```ts
createNextAuthRoutes({
  storage,
  config: { origin, appId },
  onWarning: (w) => logger.warn({ code: w.code }, w.message),
});
```

Each names a real consequence. `no_requester_identity` in particular is telling you that
`trustProxyHeaders` is false, so the per-IP limit is skipped entirely — set it to `true` **only**
behind a proxy you operate (Vercel, Cloudflare, your own ingress). Setting it on a directly-reachable
app is worse than leaving it off, because `x-forwarded-for` is then caller-supplied.

---

## Step 5 — Custom `AuthStore` implementations

**If you use `{ storage }` with Redis/Upstash/Vercel KV, skip this** — `KvAuthStore` was updated for
you. This section is only for a hand-written `AuthStore`.

### Breaking contract changes

```ts
// takeChallenge now takes the PRESENTED value and returns a boolean.
- takeChallenge(appId: string, publicKey: string): Promise<string | null>;
+ takeChallenge(appId: string, publicKey: string, presented: string): Promise<boolean>;

// Two new REQUIRED methods.
+ putWalletSlot(appId: string, publicKey: string, wallet: EncryptedWallet): Promise<void>;
+ setSessionPointer(appId: string, publicKey: string, tokenHash: string): Promise<void>;
```

**Why `takeChallenge` changed:** one challenge per identity was a targeted denial of login — anyone
who could name an account overwrote the challenge its owner was mid-signature on. Challenges now
accumulate, one row per value, and consuming one must leave the others usable. Match on the exact
`(appId, publicKey, challenge)` key, not "whatever is stored for this identity".

**Why the two new methods:** the whole `UserData` blob used to be rewritten on every login and every
wallet import, so two concurrent requests resolved last-write-wins and the loser's `encryptedSecret`
was gone permanently. Both writes are now field-scoped and must not clobber unrelated fields.

```ts
// The property to honour: these two must be able to run concurrently without either losing.
await Promise.all([
  store.putWalletSlot(appId, pk, evmFundsWallet),
  store.setSessionPointer(appId, pk, tokenHash),
]);
// Afterwards BOTH the wallet and the pointer are present.
```

### Verify against the conformance suite

Do not eyeball this. The suite ships and is the acceptance bar. It returns plain
`{ name, run() }` cases that throw on failure, so it runs under whatever framework you already use:

```ts
import { authStoreConformanceCases } from "@tetrac/login-sdk/storage/conformance";

for (const c of authStoreConformanceCases(() => new MyStore(client))) {
  it(c.name, () => c.run());
}
```

The suite gained cases in this range — per-field write isolation, per-value challenges, wallet-slot
independence. A store that passed on 0.5.0 will **not** pass now, and that is the point: each new
failure is a bug your 0.5.0 store already had.

### Or delete your implementation entirely

If you hand-wrote Postgres, MySQL, or SQLite on 0.5.0 because nothing shipped, **0.6.0 ships all
three**. Deleting your store in favour of the built-in is almost always right — it carries preflight
checks that refuse to boot on a world-readable Supabase `public` schema, a non-strict MySQL that
truncates wallet blobs, or a SQLite file under a web-served directory.

```ts
import { createPostgresAuthStore, schemaFor } from "@tetrac/login-sdk/storage/sql";

// 1. Run schemaFor("postgres") against your database.
// 2. Point the SDK at it.
const store = await createPostgresAuthStore({ client: pool });
export const { GET, POST } = createNextAuthRoutes({ store, config: { origin, appId } });
```

Covers Postgres, Supabase, Neon, RDS/Aurora, Railway, Render, Fly, CockroachDB. See the
**`multi-database`** skill before writing any storage code.

**Migrating data from your hand-written schema is your job** — the shipped schema will not match
yours. Export `UserData` records and replay them through `putUser`.

---

## Step 6 — Route behaviour changes

These matter only if you wrote code that branches on them.

**`/challenge` no longer distinguishes unknown emails.** It used to answer `400 "publicKey or email
required"` for an unregistered address and `200` for a registered one — a clean account-existence
oracle. It now answers `200` with a well-formed, **unstored** challenge either way.

```ts
// ❌ This check is now always false. Delete it.
if (challengeRes.status === 400) showError("No account with that email");
```

Account existence surfaces at `/register` (409) as it always did. The SDK's own `auto` mode already
uses that path, so `registerWithEmail` → fall back to `loginWithEmail` on 409 is unchanged.

**`/challenge` always returns `pbkdf2Iterations`.** Previously omitted for records with no pinned
count, which was itself the oracle one key over. The client no longer guesses `100_000` locally — the
server is the sole authority. If you built a custom login flow that called `/challenge` directly and
supplied your own fallback, drop it and use what the server sends.

**Unknown actions return 400, not 404.** The route exists; the `action` segment names nothing, which
is a client error. Override with `unknownActionStatus: 404` if your monitoring depends on the old
shape.

**Authenticated responses carry `cache-control: no-store`.** No action needed.

---

## Step 7 — Client and React

**Nothing in `@tetrac/login-sdk/react` broke.** `AuthProvider`, `useAuth`, `useSigner`, `useUser`,
`useWallets`, `useActiveWallet`, `useExportKey`, `useBiometricUnlock` are all unchanged.

Two things worth adopting:

**`useActiveWallet()` instead of `wallets.find(w => w.role === "funds")`.** The hand-rolled version is
wrong for Web3 accounts — their identity is the connected wallet, which is not in `user.wallets` at
all. `useActiveWallet` resolves both paths and returns `encrypted: null` for an external wallet, which
is also your signal that there is nothing to export.

**Wallet slots are now bounded and replace-in-place.** A record holds at most one wallet per
`(chain, role)` — four slots, `WALLET_SLOTS`. Importing an EVM funds wallet **replaces** the existing
one rather than appending. If you relied on append-order (`.find()` returning the first match), that
was already a fund-misdirection bug: the old address stayed active while the user believed they had
replaced it.

**`<EmailMethod>` now auto-generates a strong passkey by default.** Previously opt-in, which meant the
out-of-the-box experience was a free-text field holding the secret that encrypts the user's wallet.
Pass `passkeyGenerator={false}` to restore the old behaviour — but read § *Why* in
`src/ui/EmailMethod.tsx` first; a typed passkey is the one input a database leak turns into an offline
attack, and it is not resettable.

---

## Upgrade checklist

- [ ] **Step 0 ran against production.** You know your `wallet` and `biometric` account counts.
- [ ] Web3 users have exported, or you have accepted the loss in writing.
- [ ] `config.origin` set to the **production** origin, identical in every environment that shares a
      database.
- [ ] `sessionHeader` / `publicKeyHeader` / `appIdHeader` / `preferPrf` removed from config; any
      manual header shim deleted.
- [ ] `PrfUnavailableError` handled on the biometric registration path.
- [ ] Custom `AuthStore`: `takeChallenge` re-signatured, `putWalletSlot` + `setSessionPointer`
      implemented, conformance suite green. Or replaced with a shipped SQL store.
- [ ] Any `challengeRes.status === 400` existence check deleted.
- [ ] `onWarning` wired, and each warning either resolved or consciously accepted.
- [ ] `allowedAppIds` set.
- [ ] `trustProxyHeaders` set to `true` **only** if a proxy you operate is actually in front.
- [ ] Smoke test on a **copy** of production data, not a fresh database — a fresh database cannot
      reproduce the derivation break, which is the entire risk of this upgrade.

## What this skill does not cover

- **Migrating data out of a hand-written 0.5.0 SQL store** into the shipped schema. Shapes differ;
  replay through `putUser`.
- **Recovering an origin-broken Web3 wallet.** It is not recoverable. Do not let anyone talk you into
  "just try both messages" — the 0.5.0 message is reproducible, so a *deliberate* dual-derivation
  compatibility path is technically possible, but it re-opens the phishing relay the origin binding
  exists to close. If someone needs it, that is a design decision to take explicitly, not a migration
  step.
- **Upgrades from 0.4.x or earlier.** Assume 0.5.0 as the floor.
