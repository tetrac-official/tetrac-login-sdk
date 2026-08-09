# PRD — Headless runtime support

| | |
|---|---|
| **Status** | Draft — awaiting decisions in §10 |
| **Date** | 2026-08-05 |
| **Target** | v1.0 (breaking changes permitted; no migration or deprecation shims) |
| **Scope** | `src/client/*`, `src/core/config.ts`, `src/react/useBiometricUnlock.ts` |
| **Owner** | TTC |

---

## 1. Summary

`@tetrac/login-sdk`'s client layer assumes a browser. Outside one it does not fail — it
**silently degrades**: session values are dropped, auth headers come back empty, and the
caller gets an object that looks like a working client and isn't.

This PRD proposes an explicit `headless` mode: one config flag, validated at construction,
that makes non-browser use a first-class supported environment instead of an accident.

The motivating case is a long-running Node process — a trading daemon that logs in with a
Web3 wallet, holds an app key, and signs on a schedule. Today that process cannot persist a
session, cannot run any wallet flow (it throws on `window.location.origin`), and finds its
vault locked after 15 seconds.

## 2. Problem

Three distinct failures, in descending order of nastiness:

**2.1 — Silent no-op session storage.** Every write in [`session.ts`](../src/client/session.ts)
is guarded by `hasWindow()`. In Node, `setSession()` stores nothing and returns normally, so
`getAuthToken()` is `null`, `authHeaders()` is `{}`, and every authenticated request 401s.
No error is raised at any point. This is the worst of the three because it is invisible.

**2.2 — Web3 flows are unreachable.** `AuthClient.clientOrigin()`
([authClient.ts:143](../src/client/authClient.ts#L143)) requires `window.location.origin`
and throws otherwise. It backs `walletLoginMessage` and `walletAppKeyMessage`, so
`connectWallet`, `loginWithWallet`, `registerWithWallet` and the `{ signMessage }` re-auth
path are all unusable headless.

**2.3 — Browser-tuned lock policy.** `armAppKey` sets a lock deadline of `autoLockMs`
(default 15 s). The *timer* is skipped without a window, but `isLocked()` enforces the
deadline by clock, so the key still expires. A daemon signing less often than every 15 s
finds `getAppKey()` null and must re-derive.

## 3. Goals

- A Node/Bun/Deno process can complete a full lifecycle: register or log in (email or Web3
  wallet), hold an app key, sign, and log out.
- Non-browser use is **declared**, and a declaration that disagrees with reality is a
  startup error, never a silent wrong path.
- One published artifact. No forked build, no duplicated vault state.
- No regression to the origin-binding guarantee (C-1) in a browser.

## 4. Non-goals

- **WebAuthn / biometric off-browser.** `navigator.credentials` and `indexedDB` have no
  meaningful equivalent. These must throw a clear error, not be emulated.
- **`/react`, `/ui`, `/ledger`.** React DOM and WebUSB/WebHID are browser-bound by nature.
- **Session persistence across process restarts.** See §10.1 — deliberately deferred.
- **Server-side rendering of the client.** Out of scope; SSR consumers use `/server`.

## 5. Current coupling — exact inventory

Everything below must be accounted for by the design. Nothing else in `src/` touches a
browser API.

| Location | Coupling | Disposition |
|---|---|---|
| [session.ts:114](../src/client/session.ts#L114) | `hasWindow()` guard | Replaced by runtime resolution |
| [session.ts:144-171](../src/client/session.ts#L144-L171) | `visibilitychange`, `freeze`, `pagehide`, `pageshow`, `storage` listeners | Skipped headless — no tabs to coordinate |
| [session.ts:205-212](../src/client/session.ts#L205-L212) | `setSession` → `localStorage` | In-process `Map` headless |
| [session.ts:278-297](../src/client/session.ts#L278-L297) | token / publicKey / email / iteration getters | Same |
| [session.ts:305-312](../src/client/session.ts#L305-L312) | `clearSession` removals | Same |
| [authClient.ts:143-151](../src/client/authClient.ts#L143-L151) | `clientOrigin()` requires `window` | Falls back to `config.origin` **only when no window exists** |
| [config.ts:209](../src/core/config.ts#L209) | `browserOrigin()` default | Unchanged; already returns `undefined` off-browser |
| [webauthn.ts:71,80](../src/client/webauthn.ts#L71) | `window.PublicKeyCredential`, `window.location.hostname` | Throws headless |
| [webauthn.ts:96,133,168](../src/client/webauthn.ts#L96) | `navigator.credentials`, `indexedDB` | Throws headless |
| [biometricUnlock.ts:165-231](../src/client/biometricUnlock.ts#L165-L231) | `localStorage` marker | Throws headless |
| [useBiometricUnlock.ts:21-39](../src/react/useBiometricUnlock.ts#L21-L39) | `localStorage` registration | React-only; out of scope |

**Not coupled, confirmed:** `core/crypto.ts` (WebCrypto is global in Node ≥18),
`core/index.ts`, all of `server/`, all of `storage/`. The `Symbol.for("tetrac.vault")`
global works identically in any realm.

## 6. Design

### 6.1 The flag

```ts
/**
 * This client runs outside a browser — a trading daemon, a bot, a CI job.
 * Default false. Validated at construction against the actual runtime.
 */
headless: boolean;
```

### 6.2 Validation at construction (the load-bearing part)

The flag is a **declaration the SDK checks**, not a switch it obeys. Detection stays
automatic; disagreement is fatal.

| Declared | Runtime | Result |
|---|---|---|
| `false` (default) | browser | Current behaviour, unchanged |
| `false` | no `window` | **Throw.** This is today's silent-no-op bug, made loud. |
| `true` | no `window` | Headless behaviour |
| `true` | browser | **Throw.** Opting a real page out of the unspoofable origin is how C-1 returns. |

### 6.3 Behaviour under `headless: true`

- **Session values** live in a module-scope `Map` on the same `Symbol.for` global as the
  vault, so every bundle copy shares one store — the same reasoning that already governs
  `memoryAppKey`.
- **Origin** comes from `config.origin`, which is already mandatory.
- **Lifecycle listeners** are not bound. There is no tab to hide and no sibling tab to
  signal, so `lockOnHide` and the cross-tab `storage` sentinel are inert by construction.
- **WebAuthn / biometric** throw `BrowserOnlyError` naming the method, rather than a raw
  `ReferenceError: navigator is not defined`.

### 6.4 Why not conditional exports

`package.json` could carry `"browser"` / `"node"` conditions and ship two builds. It should
not, and the reason is already documented in this codebase:
[session.ts:30-42](../src/client/session.ts#L30-L42) explains that tsup inlines the vault
module into multiple subpath bundles, and that without the shared `Symbol.for` registry each
copy would own a **separate `memoryAppKey`** — `login()` arming one copy while `getAppKey()`
read another, "never-armed" one.

Conditional exports multiply exactly those copies. That is the dual-package hazard aimed
directly at the vault. The environmental differences here are three small behaviours, not a
second implementation, so they belong behind a runtime branch inside one artifact.

### 6.5 Lock policy

`autoLockMs` stays configurable and keeps its 15 s default for browsers. Under `headless`
the default is unsuitable — a daemon is not a human tab-switching — so the resolved config
should either require an explicit `autoLockMs` or adopt a longer headless default. See
§10.2.

## 7. Security invariants

These must hold after the refactor, and each needs a test:

1. **A browser can never reach the `config.origin` fallback.** A page cannot delete its own
   `window`, and `headless: true` in a browser throws, so the unspoofable path is the only
   path a page can take. This is what keeps C-1 closed.
2. **The app key stays memory-only.** Headless session storage holds the token, publicKey,
   email and pinned iteration count — the same non-secret set `localStorage` holds today.
   The app key is *not* added to it.
3. **No silent degradation anywhere.** Every environment mismatch raises at construction.
4. **WebAuthn cannot be stubbed.** Gate mode was removed precisely so a weaker path could
   not exist; headless must not reintroduce one under a different name.

## 8. Test plan

- Full `AuthClient` lifecycle in the node environment with **no `window` shim at all** —
  register, login, sign, logout, against real handlers over `MemoryAdapter`.
- Both mismatch cases throw at construction, with a message naming the fix.
- Web3 wallet login headless: the message is built from `config.origin` and verifies
  server-side; a *browser* client with a different `window.location.origin` does not.
- Every WebAuthn/biometric entry point throws `BrowserOnlyError` headless.
- Existing browser suites pass unchanged.
- **Delete the hand-rolled `window` polyfills** in `tests/auth-client.test.ts` and
  `tests/client-logout.test.ts`. They exist only to work around this problem and are the
  clearest evidence it needs fixing.

## 9. Rollout

Per project rule, v1.0: breaking changes are taken directly, with no migration path or
deprecated aliases.

- `AuthConfig` gains a required-with-default `headless: boolean`.
- Node consumers who today get a silently broken client will now get a startup error. That
  is the intended outcome — those deployments are already broken and do not know it.

## 10. Open questions

**10.1 — Session persistence across restarts.** An in-process `Map` dies with the process,
so a daemon re-authenticates on every boot. For email accounts that means re-deriving the
app key (600k PBKDF2, ~7 s); for wallet accounts it means re-signing. Acceptable for v1.0?
The alternative is an injectable storage interface, which subsumes the flag and is a larger
API surface.

**10.2 — Headless `autoLockMs`.** Options: (a) keep 15 s and let callers raise it, (b) use a
longer headless default, (c) require an explicit value under `headless` so the choice is
deliberate. (c) is most in keeping with the rest of this design, at the cost of one more
mandatory field.

**10.3 — Should `headless` be inferred rather than declared?** `typeof window === "undefined"`
is already decisive, so the flag adds no detection power. Its only job is turning a silent
wrong path into a loud one. If that is not judged worth a config field, the alternative is to
auto-detect and simply throw on the *behaviours* that cannot work — smaller API, weaker
signal at startup.

**10.4 — Bun / Deno / edge runtimes.** Workers define `self` but not `window`, and some edge
runtimes define neither while still being browser-ish. Is edge a target, or is "no `window`
means headless" a sufficient rule for v1.0?
