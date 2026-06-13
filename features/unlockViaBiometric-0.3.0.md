# Feature PRD — `unlockViaBiometric`: optional biometric unlock for any account

Add a first-class SDK capability that lets **any** account (email, web3, or biometric-primary)
opt into unlocking the vault — and revealing/​signing — with a device biometric (Touch ID / Face
ID), instead of re-entering a passkey or re-signing a wallet message every time.

The biometric secret does **not** become the app key (that only works for biometric-primary
accounts). Instead it **wraps the account's existing app key**: on enable we encrypt the current
app key under a passkey-derived secret; on unlock a biometric assertion unwraps it and arms the
vault. Wallets stay in their canonical encryption — we add one wrapped-key blob, not a re-encrypt
of every wallet.

- **Status:** Draft v1 — design proposal (longer-term, additive, non-breaking)
- **Target SDK version:** `0.3.0` (additive minor; new exports, no breaking changes)
- **Consumer follow-up:** once shipped, `next-ttc` replaces its broken settings-panel biometric toggle (see §9) — that work is **out of scope here** and lands in the app after this releases.

---

## 1. Motivation — the gap this closes

The SDK currently models biometric as a **standalone primary auth method**: `registerWithBiometric`
makes the WebAuthn PRF/gate secret *be* the app key (`deriveAppKey({ registration })` returns
`derivePasskeySecret(reg)`). There is **no way to add biometric to an existing email/web3 account**.

A consumer (`next-ttc`) tried to expose "enable biometric" on any account via the standalone
`registerPasskey` + persisting a `PasskeyRegistration`. That is **actively harmful**: the registered
passkey's secret is unrelated to an email/web3 account's real app key (`PBKDF2(passkey,email)` or
`SHA256(sig)`), so feeding `{ registration }` to `revealSecret`/`unlock` derives the **wrong key**
and fails — it locks the user out of their own keys instead of protecting them.

The pre-SDK app solved this with an add-on gate that re-encrypted every wallet blob under a passkey
`CryptoKey` (`_passkey_enc`). This PRD brings the equivalent capability into the SDK, but cleaner:
wrap **one** thing (the app key), not N wallets.

**Goal:** any account can add an optional biometric unlock that is a true convenience/second-factor
layer over its existing credential — never a replacement, never a footgun.

---

## 2. Design

### 2.1 Core idea — wrap the app key, don't replace it

```
enable  (vault must be UNLOCKED):
  appKey = getAppKey()                       // the account's real key (any method)
  reg    = registerPasskey(cfg, userName)    // PRF or gate credential
  secret = derivePasskeySecret(reg)          // Touch ID -> high-entropy hex secret
  blob   = AES-GCM-encrypt(appKey, key=HKDF(secret))   // authenticated wrap (NEW crypto, see §4)
  persist(reg, blob)                          // per-credential, per-device

unlock (re-arm the vault with a biometric):
  secret = derivePasskeySecret(reg)          // Touch ID -> same secret
  appKey = AES-GCM-decrypt(blob, key=HKDF(secret))
  armAppKey(appKey)                           // vault unlocked; 15s auto-lock window restarts
```

Because we recover the **account's own app key**, every downstream path (wallet decrypt, sign,
reveal) works unchanged for email / web3 / biometric-primary accounts alike.

### 2.2 Why this is safe to persist at rest

The wrapped blob may sit in storage because **unwrapping always requires a fresh biometric
assertion**:
- **PRF mode:** the wrapping secret is the PRF output — never persisted, re-derived only inside a
  successful `navigator.credentials.get({ userVerification: "required" })`. Storage-scraping XSS
  reads ciphertext it can never unwrap.
- **Gate mode:** the secret is held in IndexedDB wrapped under a **non-extractable** AES-GCM
  `CryptoKey` (existing `gateStore`/`gateLoad`), released only after a successful assertion. Same
  property — no Touch ID, no unwrap.

This is the legacy `_passkey_enc` security property, applied to the app key instead of each wallet.

### 2.3 Enable requires an unlocked vault

You can only wrap a key you currently hold, so `enableBiometricUnlock` requires `getAppKey() !==
null` (call it right after login, or after a passkey/sig `unlock`). If the vault is locked it throws
`VaultLockedError`.

### 2.4 Device-bound, additive — never the recovery path

Biometric unlock is per-device (WebAuthn credentials are device-bound) and **never** the account
recovery mechanism. The account's primary credential (email passkey / wallet signature / primary
passkey) remains the cross-device recovery path. Losing the device falls back to the primary method;
`{ biometricUnlock }` is a convenience layer on top, not a substitute.

---

## 3. API surface (additive)

### 3.1 `@tetrac/login-sdk/client` — new functions

```ts
/** True if a biometric-unlock blob is registered on this device. Sync. */
export function hasBiometricUnlock(): boolean;

/**
 * Wrap the CURRENT vault app key under a freshly-registered passkey secret and
 * persist it. Requires the vault to be unlocked (throws VaultLockedError otherwise).
 * Returns the PasskeyRegistration the app must persist to call unlockViaBiometric later.
 */
export function enableBiometricUnlock(
  config: WebAuthnConfig,
  userName: string,
): Promise<PasskeyRegistration>;

/**
 * Touch ID -> derive the passkey secret -> unwrap the stored app key -> armAppKey().
 * Re-arms the vault for ANY account. Throws if no blob/registration or the
 * assertion is declined.
 */
export function unlockViaBiometric(registration: PasskeyRegistration): Promise<void>;

/** Remove the wrapped blob + gate secret + on-device credential state. */
export function disableBiometricUnlock(registration: PasskeyRegistration): Promise<void>;
```

### 3.2 New `ReauthCredentials` variant (so `reveal`/`unlock` accept biometric on any account)

```ts
export type ReauthCredentials =
  | { passkey: string }                                       // email
  | { signMessage: (m: Uint8Array) => Promise<Uint8Array> }   // web3
  | { registration: PasskeyRegistration }                     // biometric-PRIMARY (secret IS the app key)
  | { biometricUnlock: PasskeyRegistration };                 // NEW: biometric UNLOCK (secret unwraps the app key)
```

`AuthClient.deriveAppKey` gains the branch:
```ts
if ("biometricUnlock" in creds) {
  const secret = await derivePasskeySecret(creds.biometricUnlock); // Touch ID
  return unwrapAppKey(creds.biometricUnlock.credentialId, secret); // AES-GCM-decrypt the stored blob
}
```
With this, the existing `unlock(creds)` and `revealSecret(wallet, creds)` work with a biometric for
email/web3 accounts **with no other changes** — and `revealSecret` still runs a fresh ceremony every
time (the "re-auth to reveal" guarantee holds; auto-lock window is unaffected).

> **Important distinction (must be documented in code):** `{ registration }` = biometric-primary
> account, where `derivePasskeySecret` *is* the app key. `{ biometricUnlock }` = the secret *unwraps*
> a stored app key. They are NOT interchangeable; feeding `{ registration }` for an email/web3
> account is the exact bug this feature exists to prevent.

### 3.3 `@tetrac/login-sdk/react` — new hook

```ts
export function useBiometricUnlock(): {
  available: boolean;     // isBiometricAvailable()
  isEnabled: boolean;     // hasBiometricUnlock()
  enable: (userName?: string) => Promise<void>;  // wraps current app key (vault must be unlocked)
  disable: () => Promise<void>;
  unlock: () => Promise<void>;                    // re-arm the vault via Touch ID
  loading: boolean;
  error: Error | null;
};
```
`useExportKey` needs no change — consumers pass `reveal({ biometricUnlock: reg })`. Optionally a
later convenience: `useExportKey(wallet, { preferBiometric: true })` resolves the registration
itself.

### 3.4 `AuthClient` methods (thin wrappers, same names)

`enableBiometricUnlock`, `unlockViaBiometric`, `disableBiometricUnlock`, `hasBiometricUnlock` —
delegating to the client functions so `createAuthClient()` users get them too.

---

## 4. Cryptography & storage

- **Wrap cipher: WebCrypto AES-256-GCM (authenticated).** This is NEW data with no
  byte-compat constraint, so unlike the compat-locked crypto-es AES-CBC used for wallets
  (`docs/5-PRD-FABLE-AUDIT.md` §4, D1), the wrap blob uses authenticated encryption with a random
  12-byte IV — tamper-evident and AEAD. Derive the AES key from the passkey secret via
  `HKDF-SHA-256` (salt = credentialId bytes, info = `"ttc-biometric-unlock-v1"`) so the raw PRF/gate
  secret is never used directly as a key.
- **Blob shape:** `{ v: 1, iv, ciphertext }` (versioned for future rotation).
- **Storage location:** a new object store `unlock_blobs` in the existing `ttc_passkey_store`
  IndexedDB DB, keyed by `credentialId` — keeps all biometric-unlock state in one place alongside
  gate secrets. (localStorage would also be acceptable since the blob is authenticated ciphertext,
  but co-locating keeps cleanup atomic.)
- **No new server surface.** This is entirely client/device-local; the server never sees the wrapped
  blob, the app key, or the biometric secret.

---

## 5. Lifecycle & edge cases

| Event | Behavior |
|---|---|
| Enable while vault locked | throws `VaultLockedError` — caller must `unlock` first |
| `unlockViaBiometric` after auto-lock | Touch ID -> unwrap -> `armAppKey` (15s window restarts); no widening of the signing window |
| Reveal via `{ biometricUnlock }` | fresh assertion each reveal; does NOT arm the session (consistent with `revealSecret`) |
| App key changes (e.g. user changes their email passkey) | stale blob -> unwrap yields an old key -> decrypt fails. Detect on `unlock`/reveal failure and prompt re-enable. (Email/web3 app keys are deterministic and stable, so this is rare.) |
| New device | no blob present -> `hasBiometricUnlock()` false -> user re-enables after a primary-method login |
| `disable` / logout | `disableBiometricUnlock` removes the blob + gate secret; `clearSession` should also purge `unlock_blobs` for the credential |
| Lost device / declined biometric | fall back to the account's primary credential — biometric is never the only path |

---

## 6. Security model & threats

- **Restores the legacy gate property:** XSS can read the wrapped blob but cannot unwrap it without a
  user biometric assertion (PRF secret never stored; gate secret non-extractable + assertion-gated).
- **Second factor, not a backdoor:** unlock requires *something you are* (biometric) to release
  *something you have/know* (the wrapped app key originally derived from the primary credential).
- **No reduction of existing guarantees:** auto-lock (15s) and lock-on-hide still apply after a
  biometric unlock; reveal still re-auths every time; the app key still never touches the network or
  localStorage in plaintext.
- **Threat not covered:** a compromised authenticator / OS-level biometric bypass — out of scope, as
  for all WebAuthn. Document that biometric unlock inherits the platform authenticator's assurance.

---

## 7. Testing

- **Unit (jsdom + mocked WebAuthn):** enable->unlock round-trips the exact app key; wrong/declined
  assertion fails closed; PRF and gate modes both round-trip; `enable` throws when locked; `disable`
  purges the blob; AES-GCM tamper (flip a ciphertext byte) -> decrypt throws.
- **Cross-method:** an email app key (`PBKDF2`) and a web3 app key (`SHA256(sig)`) each wrap/unwrap
  identically — assert `unlockViaBiometric` arms the same key `enable` captured.
- **Distinction guard:** `{ registration }` (primary) and `{ biometricUnlock }` resolve to *different*
  keys for the same credential — a regression test that catches re-confusing the two.
- **Lifecycle:** auto-lock still fires post-unlock; reveal does not arm; logout purges blobs.
- Use ephemeral keys only — never real key material in tests (project rule).

---

## 8. Phased plan

1. **Crypto + storage primitives** (`src/client/biometricUnlock.ts`): HKDF + AES-GCM wrap/unwrap,
   `unlock_blobs` IndexedDB store, `wrapAppKey`/`unwrapAppKey`.
2. **Client API:** `enableBiometricUnlock` / `unlockViaBiometric` / `disableBiometricUnlock` /
   `hasBiometricUnlock`; export from `client/index.ts`.
3. **AuthClient + ReauthCredentials:** add `{ biometricUnlock }` to the type and `deriveAppKey`;
   thin `AuthClient` wrappers; ensure `clearSession` purges blobs.
4. **React:** `useBiometricUnlock` hook; export from `react/index.ts`. (Optional `preferBiometric`
   on `useExportKey`.)
5. **UI (optional):** a toggle in `LoginPanel`/`ExportKeyPanel` or a standalone `<BiometricUnlock>`
   control (kept generic; consumers may keep their own branded UI).
6. **Docs + tests:** this file -> `docs/`, README section, the test matrix in §7.
7. **Release `0.3.0`**, then the consumer migration (§9).

---

## 9. Consumer follow-up (next-ttc — OUT OF SCOPE here, tracked for after release)

Once `0.3.0` ships, `next-ttc` should:
- Replace `usePasskeySettings.registerPasskey()` (which today registers an unrelated passkey and
  breaks reveal) with `enableBiometricUnlock` via `useBiometricUnlock().enable()`.
- Add the `{ biometricUnlock: reg }` path to the dashboard reveal cards (`DashboardKeys`,
  `DashboardOrderlyKeys`) so an email/web3 user who enabled it reveals with Touch ID.
- **Fix the latent bug regardless of this feature:** gate the existing `{ registration }` reveal
  path on `useUser()?.authMethod === "biometric"`, so a settings-panel passkey on an email/web3
  account can never hijack reveal and derive the wrong key.
- Make the settings-panel biometric toggle a real "biometric unlock" control for any account.

---

## 10. Risks & mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Persisting a wrapped app key broadens the at-rest surface | Medium | Unwrap is biometric-gated (PRF never stored / gate non-extractable); authenticated AES-GCM; documented threat model |
| Confusing `{ registration }` (primary) with `{ biometricUnlock }` (wrap) | High | Distinct creds variants + regression test (§7) + explicit code docs; the consumer bug in §1 is the cautionary example |
| Stale blob after app-key change orphans unlock | Low | Detect unwrap/decrypt failure -> prompt re-enable; email/web3 keys are deterministic so rare |
| Per-device re-enable friction | Low | By design; primary credential is the cross-device path; document clearly |
| Auto-lock bypass perception | Low | Biometric unlock obeys the same 15s/lock-on-hide window; reveal never arms |

---

## 11. Non-goals

- Not a replacement for the primary credential, and not an account-recovery mechanism.
- No change to wallet-at-rest encryption (still crypto-es AES-CBC for byte-compat).
- No new server endpoints or stored data.
- No change to the existing `{ registration }` biometric-primary flow.

---

## 12. Acceptance criteria

- [ ] `enableBiometricUnlock` (vault unlocked) -> `unlockViaBiometric` round-trips the exact app key for email, web3, and biometric-primary accounts.
- [ ] `revealSecret(wallet, { biometricUnlock })` and `unlock({ biometricUnlock })` succeed for email/web3 accounts; reveal runs a fresh assertion and does not arm the vault.
- [ ] Wrapped blob is authenticated (AES-GCM); a tampered blob fails closed; a declined/absent biometric fails closed.
- [ ] `{ registration }` and `{ biometricUnlock }` provably resolve to different keys (regression test).
- [ ] `disableBiometricUnlock` and `clearSession` purge the blob + gate secret.
- [ ] Additive, non-breaking: existing exports/behaviors unchanged; `0.3.0` minor bump; `npm run typecheck` + `npm test` green; new tests cover §7.
