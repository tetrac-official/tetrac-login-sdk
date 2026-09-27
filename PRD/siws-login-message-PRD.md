# PRD — SIWS-compliant wallet login message

| | |
|---|---|
| **Status** | In verification — implemented on branch v0.6.1 (8c894a1, review follow-ups uncommitted); automated gate (§8.1, §8.1a) passed; manual release gate (§8.2) not run. Review amendments in §13 |
| **Date** | 2026-09-27 |
| **Target** | 0.6.1 (breaking changes permitted; no migration or deprecation shims) |
| **Scope** | `src/core/index.ts`, `src/core/config.ts`, `src/client/authClient.ts`, `src/server/signature.ts`, `src/server/routes.ts`, `tests/*`, `scripts/smoke-multi-app.mjs`, `scripts/verify-siws-login.mjs`, `.github/workflows/ci.yml`, `package.json` |
| **Closes** | Web3 login fails on Phantom 26.30.x: *"The app's signature request cannot be shown due to invalid formatting."* |
| **Owner** | TTC |

---

## 1. Summary

Phantom 26.30.x refuses to display the first signature of the Web3 handshake — the
ownership proof built by `walletLoginMessage`. The message opens with the Sign In With
Solana (SIWS) preamble but is not a valid SIWS message, and Phantom now field-checks
anything that looks like SIWS. Every Phantom user is locked out of wallet login and
registration on every deployment.

The fix is to emit a message that is valid under the SIWS grammar:

```diff
- https://www.tetrac.xyz wants you to sign in with your Solana account.
-
- URI: https://www.tetrac.xyz
- Nonce: d49a44e9…4e2fc5
+ www.tetrac.xyz wants you to sign in with your Solana account:
+ 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
+
+ Sign in to prove you own this wallet. This request does not send a transaction or cost any fees.
+
+ URI: https://www.tetrac.xyz
+ Version: 1
+ Nonce: d49a44e9…4e2fc5
```

One builder changes. `verifySolanaSignature` keeps its signature, so the routes are
untouched. The app-key messages — key-derivation input — do not change.

## 2. Problem

**2.1 — Symptom.** Reproduced 2026-09-27:

| Wallet | `https://www.tetrac.xyz` (0.6.0) | `http://localhost:3000` (0.6.0) |
|---|---|---|
| Phantom 26.30.2, Chrome extension | ✗ "…cannot be shown due to invalid formatting" | ✗ same |
| Solflare extension, fresh wallet | ✓ | ✓ |

Production and local run identical SDK and app code, so this is wallet behavior, not a
deployment. The error is thrown by the extension (the text appears nowhere in
`node_modules`) on the first `signMessage` of `walletHandshake`, immediately after
`POST /challenge`.

**2.2 — Root cause.** [`walletLoginMessage`](../src/core/index.ts#L26) produces:

```
${origin} wants you to sign in with your Solana account.\n\nURI: ${origin}\nNonce: ${challenge}
```

It borrows the SIWS preamble and breaks the SIWS grammar in three places:

| SIWS requires | Current message |
|---|---|
| Line 1 names the bare authority (`host[:port]`); the scheme lives only in `URI:` | `https://www.tetrac.xyz …` — full origin |
| Preamble ends with `:` | ends with `.` |
| Line 2 is the signer's base58 address | missing |

The reference parser (`parseSignInMessageText`, `@solana/wallet-standard-util` 1.1.2)
returns `null` for it. Phantom parses any `signMessage` payload that resembles SIWS and
refuses to render one that fails its field checks; Solflare shows it as plain text,
which is why only Phantom broke. Other projects hit the same error the same week
(Reown AppKit #5801, filed 2026-09-26) and fixed it by putting the bare authority on
line 1 (fobs #2) and keeping the statement pure ASCII (Pantessa #830) — see §12.

**2.3 — Scope of breakage.** Affected: `loginWithWallet`, `connectWallet` and
`registerWithWallet` — all three run `walletHandshake`. Not affected: re-auth, unlock and
reveal (they sign only the app-key message) and `proveIdentity` (email and biometric
registration; signed in-process by the SDK-generated identity key, no wallet UI) — though
`proveIdentity` uses the same builder and changes with it.

**2.4 — The domain line protects nobody today.** The message is origin-bound so a
signature for one site cannot be relayed to another. But the SDK client is not the only
thing that can ask a wallet to sign: a hostile page can fetch a real challenge from a
victim's unauthenticated `/challenge` and request a signature over the victim's exact
text directly. Today the only defense is the user reading the first line of the prompt.
SIWS exists so the *wallet* can compare the domain line with the page making the
request — which it cannot do while the message does not parse.

## 3. Goals

- Phantom (current release, desktop and mobile) renders the request and signs it.
- The message follows the SIWS ABNF. The reference parse and byte-for-byte round-trip
  through `createSignInMessageText` is a necessary check, not a validator — the reference
  parser is a loose regex that accepts a scheme on line 1, `URI: null` or a base64url nonce —
  so the builder guards its variable fields and the tests assert the field grammar directly.
- Origin binding is unchanged: the client builds from `window.location.origin`, the
  server from `config.origin`. The scheme stays in the signed bytes (the `URI:` line).
- The signer's address is part of the signed text.
- Ledger off-chain envelopes keep working.
- Nothing else moves: app-key messages, auth-key message, challenge format, storage,
  routes, the `/challenge` response, and `verifySolanaSignature`'s signature.

## 4. Non-goals

- **Wallet Standard `solana:signIn`** (wallet-built message, one-click connect + sign).
  It needs adapter plumbing beyond the `signMessage` callback the SDK takes, and the
  Ledger path does not support it. Separate PRD.
- **A Ledger clear-signable login message.** SIWS requires line breaks, so blind-signing
  behavior is unchanged from 0.6.0. The legacy-envelope login payload grows from one APDU
  (~208 bytes) to two (~354 bytes, `hw-app-solana` chunks at 255); no automated test covers
  the transport, so §8.2 splits the Ledger row by envelope.
- **Changing the app-key messages.** They are key-derivation input; changing them
  re-derives every Web3 account's key (§11.5).
- **`Issued At` / `Expiration Time`** (§11.2).

## 5. Current code — exact inventory

| Location | What it does | Change |
|---|---|---|
| [core/index.ts:26](../src/core/index.ts#L26) | `walletLoginMessage(challenge, origin)`; docstring at L11 calls it "SIWE-shaped" | Rewrite (§6.1) |
| [client/authClient.ts:421](../src/client/authClient.ts#L421) | `walletHandshake` — external wallet signs it | Pass `address: publicKey` |
| [client/authClient.ts:397](../src/client/authClient.ts#L397) | `proveIdentity` — SDK identity key signs it at email/passkey registration | Pass `address: identity.publicKey` |
| [server/signature.ts:47](../src/server/signature.ts#L47) | `verifySolanaSignature` rebuilds it from `config.origin` | Pass `address: publicKeyBase58` |
| [server/routes.ts:669](../src/server/routes.ts#L669), [:781](../src/server/routes.ts#L781), [:841](../src/server/routes.ts#L841) | `register` (external-wallet signature or identity-key proof), `loginWallet`, `connectWallet` call `verifySolanaSignature(body.publicKey, …, config.origin)` | None |
| [server/routes.ts:255](../src/server/routes.ts#L255) | `createAuthHandlers` resolves the server config | Validate `config.origin` (§6.3) |
| [core/config.ts](../src/core/config.ts) | `resolveConfig` requires `origin` but accepts any string; also runs in the browser ([authClient.ts:153](../src/client/authClient.ts#L153), via `AuthProvider`) | Unchanged; add `parseOrigin` (§6.3) |
| [core/crypto.ts:181](../src/core/crypto.ts#L181) | `generateChallenge()` — 64 hex chars | None — already a valid SIWS nonce |
| 15 test files, [scripts/smoke-multi-app.mjs](../scripts/smoke-multi-app.mjs) | Build the message positionally. Neither is type-checked (`tsconfig` excludes `tests`; ts-jest runs with `diagnostics: false`) | Update call sites (§8.1) |

## 6. Design

### 6.1 The message

```ts
/** SIWS statement. Printable ASCII from the RFC 3986 reserved/unreserved classes plus
 *  space — Phantom rejects a statement containing an em dash, curly quote or NBSP.
 *  No line breaks (SIWS forbids them in the statement). */
export const WALLET_LOGIN_STATEMENT =
  "Sign in to prove you own this wallet. This request does not send a transaction or cost any fees.";

export function walletLoginMessage(input: {
  challenge: string; // server-issued, single-use — the SIWS nonce
  origin: string; // client: window.location.origin; server: config.origin
  address: string; // signer's base58 public key
}): string {
  const url = parseOrigin(input.origin); // bare http(s) origin or throw (§6.3)
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(input.address)) throw new Error("[tetrac] …");
  if (!/^[A-Za-z0-9]{8,}$/.test(input.challenge)) throw new Error("[tetrac] …");
  return (
    `${url.host} wants you to sign in with your Solana account:\n` +
    `${input.address}\n\n` +
    `${WALLET_LOGIN_STATEMENT}\n\n` +
    `URI: ${url.origin}\n` +
    `Version: 1\n` +
    `Nonce: ${input.challenge}`
  );
}
```

| Line | Value | SIWS rule |
|---|---|---|
| 1 | `url.host` — `www.tetrac.xyz`, `localhost:3000` | `message-domain`: authority, no scheme; `URL` drops default ports |
| 2 | base58 address | `32*44` base58 characters |
| 4 | fixed statement | `1*( reserved / unreserved / " " )`, no LF |
| 6 | `URI: ${url.origin}` | RFC 3986 URI; keeps the scheme in the signed bytes |
| 7 | `Version: 1` | only `"1"` is defined |
| 8 | `Nonce: ${challenge}` | `8*( ALPHA / DIGIT )` — 64 hex characters qualify |

Verified against `@solana/wallet-standard-util` 1.1.2 for `http://localhost:3000`,
`https://www.tetrac.xyz` and `HTTPS://WWW.Tetrac.xyz:443/`: every field parses, and
`createSignInMessageText(parseSignInMessageText(m)) === m`. Size: 316 bytes typical,
at most 806 bytes for a 253-character host with an explicit port — under the 1212-byte
Ledger cap. The message is pure
printable ASCII plus LF, so the envelope format stays `RestrictedAscii`.

**Named parameters.** Challenge, origin and address are all plain strings. Transposed
positionally, they still produce a well-formed message that simply never verifies — a
silent, total login outage. Named fields make every `src/` call site type-checked.

**Guards.** Test and script call sites are not type-checked, and the reference parser
accepts anything on the address line — a call missing `address` would sign the string
`"undefined"`. The builder therefore throws on an address outside SIWS `32*44` base58, a
nonce outside `8*( ALPHA / DIGIT )` (which also enforces §11.4 at runtime), and an origin
`parseOrigin` rejects. On the server the throw lands in `verifySolanaSignature`'s `try`
and becomes `false`, the same as an invalid public key.

**One `URL` parse drives both lines**, so `host` and `origin` cannot disagree for an
http(s) origin, and default ports and IDN hosts (punycode) canonicalize identically on
client and server. Non-web schemes are rejected: their WHATWG `URL.origin` is the string
`"null"`, which would sign `URI: null`.

### 6.2 Call sites

```ts
// client — walletHandshake
walletLoginMessage({ challenge, origin: this.clientOrigin(), address: publicKey });
// client — proveIdentity
walletLoginMessage({ challenge, origin: this.clientOrigin(), address: identity.publicKey });
// server — verifySolanaSignature (public signature unchanged)
walletLoginMessage({ challenge, origin, address: publicKeyBase58 });
```

The server uses the same string the client sent as `body.publicKey` and had signed. The
`new PublicKey(publicKeyBase58)` that follows already rejects anything that is not a
valid 32-byte base58 key.

### 6.3 Validate `config.origin` at construction

The builder now parses the origin. A config origin that does not parse would make
`verifySolanaSignature` throw inside its `try` and return `false` for every wallet login
and registration — an outage with no error anywhere. `createAuthHandlers` therefore calls
`parseOrigin(config.origin)` right after `resolveConfig` and throws at boot.
`parseOrigin` (exported from `./core`) runs on `normalizeOrigin(origin)` and requires:

- it parses as a URL with protocol `http:` or `https:`;
- no username or password;
- `pathname === "/"`, and no `?` or `#` anywhere in the string (an empty query or fragment
  leaves `search`/`hash` empty).

The stored value is not rewritten. Server-side, `config.origin` feeds only
`verifySolanaSignature`.

**Not in `resolveConfig`.** The browser runs `resolveConfig` too (`AuthClient`'s
constructor, reached from `AuthProvider` during render), defaulting to
`window.location.origin`, but the client never reads `config.origin`: every message it
signs is built from `window.location.origin`. Validating there would protect nothing and
would make an opaque-origin page (`"null"`: `file://`, sandboxed iframes) or a malformed
`NEXT_PUBLIC_SITE_ORIGIN` crash the React tree, taking email and passkey login down with
wallet login. A client on a non-http(s) page instead gets the builder's `[tetrac]` error
at the point of wallet use.

### 6.4 Alternatives considered

| Option | Verdict |
|---|---|
| **A. Valid SIWS over `signMessage`** (this PRD) | Chosen. Works in every wallet — SIWS-aware ones render a sign-in UI, the rest show text — and lets the wallet check the domain (§2.4). |
| **B. Drop the preamble** (`Sign in to … Site: … Nonce: …`) | Also fixes Phantom, but gives up wallet-side domain checks and bets on Phantom never widening its heuristic. |
| **C. Wallet Standard `solana:signIn`** | Best UX, but a new client API, adapter plumbing, and no Ledger path. Future PRD (§4). |

## 7. Security invariants

Each needs a test:

1. **Origin binding.** A signature over the message for origin A never verifies at B —
   including `http` vs `https` on the same host (the `URI:` line) and different ports.
   The server's origin comes from `config.origin`, never from the request.
2. **Address binding.** The server rebuilds line 2 from `body.publicKey`, so a signature by
   B over a message naming A, submitted as B, fails (control: naming B verifies). The
   line's main value is wallet-side: the wallet can check it against the signing account.
3. **Single-use, TTL-bound challenges** — unchanged.
4. **App-key messages are byte-identical.** `walletAppKeyMessage` and
   `walletAppKeyMessageHw` get golden-string tests; today
   [audit-crypto.test.ts](../tests/audit-crypto.test.ts#L91) only checks them relative to
   each other.
5. **ASCII only.** Every byte is `0x20–0x7e` or `0x0a`, and the statement matches the RFC
   3986 class. Guards against a copy edit reintroducing an em dash.

## 8. Test plan

### 8.1 Automated

- **New `tests/siws-login-message.test.ts`:**
  - golden string for a fixed input;
  - reference round-trip: `parseSignInMessageText` recovers every field and
    `createSignInMessageText` reproduces the bytes. Adds `@solana/wallet-standard-util` as a
    **devDependency**, pinned exact — test-only, never a runtime dependency;
  - domain has no scheme: `http://localhost:3000` → `localhost:3000`,
    `https://x.example:443/` → `x.example`; case and trailing slash normalized; IDN →
    punycode;
  - byte class and statement class (invariant 5); ≤ 1212 bytes with a 253-character host;
  - direct field-grammar assertions on the parse (domain has no `://`, equals
    `new URL(uri).host`, `uri !== "null"`) — the reference parser does not enforce them;
  - builder guards throw for a bad address, nonce or origin; `parseOrigin` accept/reject
    cases;
  - `generateChallenge()` matches `^[A-Za-z0-9]{8,}$`.
  - Call `parseSignInMessageText` with a **string**; `parseSignInMessage` takes bytes, and
    with no type-checking the wrong one silently returns `null`.
- **Update the 15 files and the smoke script** that build the message: `_auth-helpers`,
  `account-creation-limit`, `audit-f1-getuser-fail-closed`, `audit-f4-creation-ceiling`,
  `audit-f5-challenge-unknown-key`, `audit-h5-identity-binding`, `challenge-lockout`,
  `concurrent-safety`, `ledger-envelope-pinning`, `ledger-login`, `multi-app`,
  `next-routes`, `server`, `signature-edge-cases`, `wallet-origin-binding`; and
  `scripts/smoke-multi-app.mjs`. Each `address` is the key the request claims, so attack
  tests keep failing for the reason they were written for.
- **`wallet-origin-binding`:** add the scheme and port mismatch cases (invariant 1), a
  relayed signature sent with hostile `Origin`/`Host`/`X-Forwarded-Host` headers (the
  request's origin is ignored), and the address case (invariant 2).
- **`ledger-login` / `ledger-envelope-pinning`:** legacy and v0 envelopes over the new
  message verify.
- **`createAuthHandlers`:** throws for `myapp.example`, `localhost:3000`,
  `https://myapp.example/app`, `https://myapp.example?x=1`, `https://myapp.example#`,
  credentials and non-web schemes; accepts `http://localhost:3000` and
  `HTTPS://MyApp.Example/`. `resolveConfig` and `new AuthClient` still accept
  `origin: "null"`.
- **`tests/auth-client.test.ts` passes unedited** — the only end-to-end check that client
  and server thread the same origin and address.
- **Golden app-key strings** (invariant 4).

### 8.1a Verification scripts

| Command | What it proves |
|---|---|
| `npm run test:siws` | Focused jest run over every suite this change touches (new SIWS suite, origin binding, config, golden app-key strings, Ledger envelopes, `auth-client` end-to-end). |
| `npm run verify:siws` | Builds `dist/` and checks the **shipped artifact** in-process for `http://localhost:3000`, `https://www.tetrac.xyz` and a non-default port: reference parse and byte-exact round-trip, bare authority on line 1, ASCII, Ledger envelope fit; right origin → 201/200; other scheme, port, site, address or nonce, replay → 401; hostile `Origin`/`X-Forwarded-Host` ignored; `createAuthHandlers` rejects bad origins. Runs in CI after Build. Mutating `dist/` to put the scheme on line 1, drop the scheme from the server's `URI:`, or skip the boot check turns it red. |
| `node scripts/verify-siws-login.mjs --url <site>/api/auth --app-id <appId> [--origin <site>]` | The same wire checks against a **running deployment**, creating one throwaway wallet account (empty wallets). A 401 on the positive check means the server is not on ≥0.6.1 or its `config.origin` differs from `--origin`. |

### 8.2 Manual — release gate

Run the live verification script against each target first, then the wallet matrix on
`http://localhost:3000` and a deployed `https` origin:

| Wallet | Expect |
|---|---|
| Phantom 26.30.x, Chrome extension | Sign-in UI showing domain, address and statement; both signatures succeed |
| Phantom mobile in-app browser (iOS, Android) | Same |
| Solflare extension | Both signatures succeed |
| Backpack extension | Both signatures succeed |
| Ledger via the direct adapter, legacy-envelope firmware (record app version) | `connectWallet` then `loginWithWallet` succeed (two-APDU payload) |
| Ledger via the direct adapter, v0-envelope firmware | Same |
| Mobile wallet over WalletConnect (QR) | Sign-in renders; both signatures succeed (`metadata.url` must equal `window.location.origin`) |
| Phantom with a Ledger account | Record the result |
| Phantom, first-time wallet | Registration (`connectWallet` for a new wallet) succeeds, not just a returning login |

**Domain check.** From a page on another origin, ask Phantom to sign a SIWS message naming
a different domain, and record whether it warns or blocks. This decides how much of §2.4
the wallet actually enforces.

## 9. Rollout

Per project rule: breaking changes are taken directly, with no dual-format acceptance.

- `walletLoginMessage` (exported from `.` and `./core`) takes
  `{ challenge, origin, address }`. next-ttc does not call it directly.
- Client and server ship in the same package, so a consumer bumps the pin and redeploys
  once. A tab opened before the deploy signs the previous message; that login fails and
  succeeds after a reload.
- Rewrite the builder's docstring: SIWS, not "SIWE-shaped".
- Client and server must run the same version, including every instance of a rolling or
  separately deployed auth service: stale tabs fail wallet login *and* email/biometric
  registration (`proveIdentity`) until reloaded.
- `CHANGELOG.md` under 0.6.1: the SIWS message and `{ challenge, origin, address }`
  signature, version lock-step, and `createAuthHandlers`' new origin check.
- **next-ttc:** pin `@tetrac/login-sdk` to 0.6.1 after publishing; `skills/login-sdk-update/SKILL.md:133`,
  which documents the message, is updated.
- **Amend `stateless-challenges-PRD.md`:** the challenge must match `^[A-Za-z0-9]{8,}$`
  (hex or base58, not base64url), and `src/server/challenge.ts`'s 64-hex shape check
  changes with it.
- The devDependency pulls four type-only packages declaring `engines: node >=22`; CI on
  Node 18/20 prints `EBADENGINE` warnings. The lockfile regeneration also syncs `viem`
  to the `^2.55.0` range already in `package.json`.

## 10. Effort

Small: one builder, three call sites, one config check, one new test file, and a
mechanical update of 15 test files. Half a day, plus the §8.2 matrix.

## 11. Open questions

**11.1 — Version.** Shipping as 0.6.1 (`package.json` is already bumped). Note that a
`^0.6.0` range — what `npm i @tetrac/login-sdk` saves — picks up this wire break; 0.7.0
would not. No TTC consumer calls the builder directly, and next-ttc pins exact.

**11.2 — `Issued At` / `Expiration Time`.** Recommended: omit. Including them shows the
request's age in the wallet, but the server must reproduce the exact timestamps, so
`/challenge` would have to return its issue time and the store keep it. Revisit only if
§8.2 shows Phantom wants them.

**11.3 — Statement wording.** Recommended: the fixed text above. An app-named statement
needs a display name in `AuthConfig`; only `appId` exists today.

**11.4 — Stateless challenges.** [stateless-challenges-PRD.md](stateless-challenges-PRD.md)
proposes `b64url(…)` challenges. Base64url contains `-` and `_`, which a SIWS nonce forbids
(`8*( ALPHA / DIGIT )`), so Phantom would reject the message again. If that PRD proceeds,
encode the token as hex or base58 — the SIWS nonce grammar forbids base64url, so
SIWS-validating wallets such as Phantom may reject it. The builder now throws on such a
nonce, so the constraint fails loudly in tests. Tracked in §9.

**11.5 — App-key message binding.** The app-key messages stay plain text, so their `Site:`
binding still depends on the user reading the prompt: a hostile page can request the
victim's exact text just as in §2.4, and that signature *is* the key. Wallet-enforced
binding there means a new message and re-deriving every Web3 key. Out of scope; flagged
for a separate decision.

## 12. References

- SIWS specification and ABNF — https://github.com/phantom/sign-in-with-solana
- Reference builder/parser — `@solana/wallet-standard-util`
  (`createSignInMessageText`, `parseSignInMessageText`)
- Reown AppKit #5801 — same Phantom error on desktop and mobile, 2026-09-26 —
  https://github.com/reown-com/appkit/issues/5801
- fobs #2 — bare authority on line 1 fixes Phantom —
  https://github.com/greyw0rks/fobs/pull/2
- Pantessa #830 — a non-ASCII statement fails Phantom's field check —
  https://github.com/Pantessa/website/pull/830

## 13. Review amendments (2026-09-27)

An adversarial review against the code and the reference parser confirmed the design —
byte-exact round-trips, the 316-byte size, the ASCII class, the nonce shape, and that
client and server put the same address string on line 2 in every flow. It changed:

- Origin validation moved from `resolveConfig` to `createAuthHandlers`, and is http(s)-only
  (§6.3).
- The builder guards address, nonce and origin (§6.1).
- The inventory gained `routes.ts:255`, `authClient.ts:153` and `scripts/smoke-multi-app.mjs`
  (§5); §2.3 gained `registerWithWallet`.
- The reference parser is a necessary check, not a validator (§3, §8.1).
- Invariant 2 is reworded to what the server actually guarantees (§7).
- Ledger APDU chunking, WalletConnect and first-time registration were added to the manual
  gate (§4, §8.2).
