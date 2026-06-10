# PRD — Fable Security & Production-Readiness Audit + Remediation

Outcome of a full read-through of `docs/1-PRD.md`–`docs/4-PRD_HOTFIX.md` against the shipped
`src/`. The hotfix lock-model (doc 4) **did land** and the three auth flows match the base PRD, but
the SDK is **not production-ready**: one prod-only storage bug, one vault-lock bypass, one WebAuthn
gate regression, and a set of server/session hardening gaps remain. This document is the work plan.

- **Status:** Draft v1 — remediation plan, actionable
- **Author:** Fable (audit) / TTC Engineering
- **Date:** 2026-06-10
- **References:** `docs/1-PRD.md` §5/§10, `docs/2-PRD_PRIVY.md` §2.6–2.7, `docs/3-DRIFTED.md`, `docs/4-PRD_HOTFIX.md`
- **Repo host:** GitLab (no GitHub Actions/CI deliverable; no LICENSE deliverable — out of scope here)

---

## 1. Scope

**In scope:** fix the blocking bugs and hardening gaps below; expand the Jest suite to cover every
new behavior. **Out of scope:** GitHub CI, LICENSE file, changesets, and any change that breaks
byte-compatibility of the encryption/derivation scheme with `next-ttc` (those are *documented*, not
*changed* — see §4).

---

## 2. Severity summary

| ID | Severity | Title | File(s) |
|---|---|---|---|
| B1 | **Blocker** | KV/Upstash adapter corrupts JSON values in prod | `src/storage/kv.ts` |
| B2 | **Blocker** | Vault lock bypassable via stale closure — signing after auto-lock | `src/react/useSigner.ts`, `useSolanaSigner.ts`, `useEvmSigner.ts`, `src/client/session.ts` |
| B3 | **Blocker** | Gate-mode WebAuthn stores app-key secret as plaintext in IndexedDB | `src/client/webauthn.ts` |
| H1 | High | Sessions never expire / never revoked; no logout endpoint | `src/server/session.ts`, `src/server/routes.ts`, `src/next/routes.ts` |
| H2 | High | Non-timing-safe credential comparison | `src/server/routes.ts` |
| H3 | High | Challenge consume is get-then-del (replay race) | `src/server/challenge.ts`, `src/storage/*` |
| H4 | High | API responses leak `passkeyHash` + `authToken` | `src/server/routes.ts`, `src/server/session.ts` |
| M1 | Medium | `incr`-then-`expire` can leave a counter with no TTL (permanent 429) | `src/server/rateLimit.ts` |
| M2 | Medium | `search-wallet` unauthenticated + unrate-limited (enumeration) | `src/server/routes.ts` |
| M3 | Medium | `import-wallet` / `register` accept unbounded, unvalidated `wallets[]` | `src/server/routes.ts` |
| M4 | Medium | `x-forwarded-for` trusted blindly (rate-limit spoof) | `src/server/http.ts`, `src/core/config.ts` |
| M5 | Medium | `<ExportKeyPanel>` posts plaintext key to RN WebView by default | `src/ui/ExportKeyPanel.tsx`, `src/ui/types.ts` |
| M6 | Medium | `lockOnHide` cannot be disabled after first bind | `src/client/session.ts` |
| D1 | Doc | Unauthenticated AES (CBC, no MAC) — compat-locked, document only | `src/core/crypto.ts` |
| D2 | Doc | Unsalted single SHA-256 server-side passkey hash — compat-locked | `src/core/crypto.ts` |
| D3 | Doc | PBKDF2 100k < OWASP guidance — configurable, default unchanged for compat | `src/core/config.ts` |

---

## 3. Remediation TODO (complete checklist)

### Blockers

- [x] **B1 — KV deserialization.** In `KvAdapter.get()`, both `@vercel/kv` and `@upstash/redis`
  auto-deserialize JSON, so a stored `UserData` blob returns as an **object**; the current
  `String(v)` yields `"[object Object]"` and breaks every `JSON.parse` in `server/session.ts`. Fix:
  return strings as-is and `JSON.stringify(...)` non-string values (round-trips cleanly through the
  `JSON.parse` consumers). Add an adapter test that stores via `set(JSON.stringify(obj))` and asserts
  `JSON.parse(get())` deep-equals the object, against a KV-like mock that auto-deserializes.
- [x] **B2 — Vault-lock bypass.** `useSigner()` captures `getAppKey()` at render time; a later
  auto-lock without a re-render leaves memoized `useSolanaSigner`/`useEvmSigner` objects able to
  decrypt with the stale key. Fix: (a) read `getAppKey()` **inside** each callback at call time and
  throw `VaultLockedError` if null; (b) drive `unlocked` via `useSyncExternalStore(subscribeLock,
  …)` so the hooks re-render on lock/unlock; (c) ensure `useSolanaSigner`/`useEvmSigner` re-evaluate
  on lock transitions. Add tests proving a signer throws `VaultLockedError` after `lockVault()` /
  auto-lock with no re-render.
- [x] **B3 — Gate-mode plaintext in IndexedDB.** `gateStore` writes a raw hex secret readable by
  any script on the origin (PRD §3 specifies a *non-extractable* key). Fix: generate a
  non-extractable WebCrypto `AES-GCM` `CryptoKey` (`extractable: false`), store the **CryptoKey** in
  IndexedDB, and wrap/unwrap the gate secret with it — so the raw secret is never persisted in
  readable form and is only recoverable after a successful userVerification assertion releases the
  flow. Keep PRF mode unchanged. Add tests for the wrap/unwrap round-trip (mock `indexedDB` +
  `crypto.subtle`).

### High

- [x] **H1 — Session lifecycle.** Give session tokens a TTL (`sessionTtlSeconds`, new config,
  default e.g. `86_400`). On login/register, **revoke the previous token** before issuing a new one.
  Add a `logout` POST route that calls `revokeSession` and wire it into `src/next/routes.ts`. Add
  tests: expired token → 401; new login invalidates the old token; logout revokes.
- [x] **H2 — Timing-safe compare.** Replace `user.passkeyHash !== body.passkeyHash` with a
  constant-time comparison (equal-length hex compare, e.g. XOR-accumulate; or WebCrypto). Add a unit
  test for the comparison helper.
- [x] **H3 — Atomic challenge consume.** Add an atomic `getdel(key)` to `StorageAdapter` (ioredis
  `GETDEL`, KV/Upstash `getdel`, Memory delete-and-return) and use it in `consumeChallenge` to close
  the replay race. Add a test that two concurrent consumes of the same challenge yield exactly one
  success.
- [x] **H4 — Response sanitization.** Strip `passkeyHash` and `authToken` from any `UserData`
  returned to the client (`asResult`, `/user-data`, `/import-wallet`). The token still travels in
  `AuthResult.authToken` (top-level) but must not be echoed inside the nested `user`. Add a test
  asserting responses never contain `passkeyHash`.

### Medium

- [x] **M1 — Rate-limit TTL safety.** Make the counter self-heal: set the TTL on the first hit and,
  if a counter is found without a TTL, (re)apply it — so a crash between `incr` and `expire` can't
  wedge an identifier at 429 forever. Add a test.
- [x] **M2 — `search-wallet` hardening.** Apply IP rate limiting; consider requiring auth or
  returning a constant-time uniform response. At minimum, rate-limit it. Add a test.
- [x] **M3 — Wallet payload validation.** Validate `wallets[]` on `register`, `connect-wallet`, and
  `import-wallet`: cap array length (e.g. ≤ 16), require each entry to have `chain ∈ {solana,evm}`,
  a non-empty string `role`, `publicKey`, and `encryptedSecret`, and bound `encryptedSecret` length.
  Reject with 400 otherwise. Add tests for over-cap and malformed entries.
- [x] **M4 — Proxy-header trust.** Add `trustProxyHeaders: boolean` (default `false`) to config.
  When false, `clientIp()` ignores `x-forwarded-for`/`x-real-ip` and uses a connection-level
  fallback identifier; when true, parse the forwarded chain. Document the deployment implication.
  Add a test for both modes.
- [x] **M5 — RN WebView default off.** Default `postToReactNativeWebView` to `false` in
  `<ExportKeyPanel>` so a generic consumer never silently exfiltrates a revealed key to a host shell;
  Shyft and other RN hosts opt in explicitly. Update the prop docs in `src/ui/types.ts`.
- [x] **M6 — `lockOnHide` honored.** Re-check the current `lockOnHide` flag inside the
  `visibilitychange` handler (bind once, gate at fire time) so `configureVault({ lockOnHide:false })`
  actually disables hide-locking. Add a test.

### Documentation-only (compat-locked — change docs, not behavior)

- [x] **D1** — Note in `src/core/crypto.ts` that `crypto-es` AES is OpenSSL-KDF + CBC with **no
  authentication tag**; tampering is undetectable. Byte-compat with `next-ttc` is required, so a move
  to WebCrypto AES-GCM is a **future versioned migration**, not part of this pass.
- [x] **D2** — Note that the server-side passkey hash is an unsalted single SHA-256 (compat with
  `next-ttc`); a salted slow verifier is the future hardening path.
- [x] **D3** — Note PBKDF2 default (100k) is below current OWASP guidance (~600k) but is kept for
  deterministic cross-device recovery compat; `pbkdf2Iterations` is configurable for new deployments.

### Test-suite expansion

- [x] New `tests/storage-kv.test.ts` — B1 round-trip + H3 `getdel` across Memory/KV-mock.
- [x] New `tests/vault-signer.test.ts` — B2 locked-signer throws (`useSigner`/`useSolanaSigner`/
  `useEvmSigner`); needs a jsdom env block or a direct-call harness.
- [x] New `tests/webauthn-gate.test.ts` — B3 gate wrap/unwrap round-trip with mocked WebCrypto+IDB.
- [x] Extend `tests/server.test.ts` — H1 (TTL/revoke/logout), H2 (timing-safe), H3 (atomic consume),
  H4 (no `passkeyHash` leak), M1 (TTL self-heal), M2 (search-wallet limit), M3 (payload validation),
  M4 (proxy trust).
- [x] Extend `tests/session.test.ts` — M6 (`lockOnHide` toggle).
- [x] All: `npx tsc --noEmit`, `npx jest`, and `npx tsup` (build) must pass.

---

## 4. Decisions

1. **No encryption-scheme change this pass** (D1/D2/D3). Byte-compat with `next-ttc` is a base-PRD
   requirement; changing the AES mode, adding a server salt, or raising the PBKDF2 default would
   break deterministic cross-device recovery for existing users. Documented for a future major.
2. **`getdel` added to the adapter interface** (H3) — every adapter (Redis/KV/Upstash/Memory)
   implements it; it's the cleanest atomic primitive and reuses cleanly for any future single-use key.
3. **Defaults stay drop-in compatible.** New config keys (`sessionTtlSeconds`, `trustProxyHeaders`)
   get conservative defaults that don't change existing wire behavior except where it's the fix
   (proxy trust defaults to *off*, which is the safer posture).

---

## 5. Acceptance criteria

- B1–B3 fixed and covered by tests; the prod KV path round-trips `UserData`, a locked signer always
  throws, and the gate secret is never persisted in readable form.
- H1–H4 and M1–M6 fixed and covered.
- D1–D3 documented in-code.
- `npx tsc --noEmit`, `npx jest`, and `npx tsup` all pass clean.
- No regression in the three login flows, deterministic recovery, or challenge replay resistance.
