# PRD — Offline / server-down resilience for `@tetrac/login-sdk`

How the SDK can let users **log in, unlock their keys, and even create new accounts while the auth
server is unreachable**, then reconcile with the server when it returns. This is a natural fit for
a self-custody SDK: the keys and the key-derivation already live on the client — the only thing
missing today is that the *ciphertext blob* lives only on the server.

- **Status:** Draft v1
- **Author:** TTC Engineering
- **Date:** 2026-06-04
- **Companion docs:** `docs/PRD.md` (base SDK), `docs/PRD_PRIVY.md` (Privy capability mapping), `docs/USE_IN_CODE.md`
- **Scope note:** "server down" means the **auth backend** (`/api/auth/*`) is unreachable. Solana/EVM **RPC is a separate service** — so once keys are unlocked offline, signing and on-chain submission still work. That is what makes offline login worth doing.

---

## 1. Does this make sense? — short answer

**Yes, with one enabling change: cache the encrypted wallet bundle on the client.**

The reason it's possible at all is tetrac's trust model. The app key (the AES key that unlocks the
wallets) is **derived on the client** and is offline-derivable for all three methods:

| Method | App-key derivation | Offline-capable? | Why |
|---|---|---|---|
| Email + passkey | `PBKDF2(passkey, email)` — `core/crypto.ts` | ✅ | Pure local computation |
| Biometric | WebAuthn PRF / `derivePasskeySecret(registration)` — `client/webauthn.ts` | ✅ | Authenticator op is local; no network |
| Web3 wallet | `SHA256(walletSignature)` over a fixed message — `client/authClient.ts` | ✅ | Signing happens in the wallet extension, locally |

So the client can always *reproduce the key*. What it cannot do today is *get the ciphertext*: the
encrypted bundle (`UserData.wallets[]`) is stored **server-side only** and fetched via
`GET /api/auth/user-data` (`server/routes.ts`). When the server is down, that fetch fails — so even
though the user can derive their key, there's nothing to decrypt.

**The fix:** cache the ciphertext bundle on the client in a **device-bound store** (IndexedDB,
wrapped under a non-extractable device key / WebAuthn PRF — **not raw `localStorage`**; see §7).
With the blob cached locally and the key derivable offline, *offline login = re-derive key →
decrypt local blob*. No server needed.

The rest of this PRD covers the three flows the user described, the storage model, the
reconciliation trigger, the device-bound caching security model, and the wallet-collision migration
flow that results when the same identity is created offline on two devices.

---

## 2. The three flows

| # | Situation | Behavior | New wallets? |
|---|---|---|---|
| **A** | Returning user · server down · **local cache exists** | **Offline login**: re-derive app key from credentials, decrypt the cached blob, grant an *offline session*. Works for email, biometric, and wallet users. | **No** — never regenerate when cached ciphertext exists (per requirement #3) |
| **B** | New user · server down · **no cache** | **Offline register**: generate wallets client-side, encrypt under the derived app key, persist under a `*_offline_<timestamp>` namespace marked "pending". User can use the wallet immediately (on-chain via RPC). | Yes — generated locally and held pending |
| **C** | Server returns · user takes an action | **Reconcile**: on a user-triggered ping (not polling), flush pending offline registrations to the server and refresh the cache. | No — replays the *already-generated* pending bundle |

---

## 3. Flow A — offline login (cache exists)

```
user submits credentials (email+passkey / biometric / wallet-signature)
        │
        ▼
derive appKey  (PBKDF2 / PRF / SHA256(sig))         ← all local, §1
        │
        ▼
load cached bundle from device-bound store  (tetrac:user:{publicKey}, §7/§8)
        │
        ▼
try decrypt wallets[0] with appKey
   ├─ success → credentials are correct → grant OFFLINE session  ✅
   └─ failure → wrong key / corrupt blob → reject                ❌
```

Key design point — **decryption is the auth check.** Normally email/biometric login round-trips to
the server to verify `passkeyHash` and issue a session token. Offline there is no server and no
token, so we authenticate by the fact that *only the correct passkey/signature can decrypt the
cached blob*. This is sound: a wrong credential yields a wrong app key, and AES decryption fails
(`decryptSecret` throws on bad key — `core/crypto.ts`).

Consequences:
- **No server session token** is issued. We introduce an explicit **offline session state** (§6),
  distinct from the existing `authenticated` / `session_expired` / `unauthenticated`.
- The app key still lives in `sessionStorage` + memory **only** — the existing invariant
  ("encryption keys never persisted") is preserved. Offline login re-derives it each time.
- **No new wallets are generated** in this flow, even though the server is down (requirement #3).
  Cached ciphertext present ⇒ decrypt-only.

This flow is identical in shape for all three methods; only the app-key derivation differs.

---

## 4. Flow B — offline registration (no cache, new user)

When there is no cache *and* the server is unreachable, a brand-new user can still get a usable
wallet:

```
derive appKey from the credentials the user provides
generate wallet bundle   (generateWalletBundle — client/wallet.ts)   ← same code as online
encrypt under appKey      (already how generateWalletBundle works)
persist a PENDING record under:   tetrac:offline:{timestamp}
mark status = "pending registration"
grant OFFLINE session (the user can transact on-chain immediately via RPC)
```

The pending record is namespaced separately from confirmed accounts (requirement #4) so the
reconciler can tell "needs to be sent to the server" from "already on the server." It must carry
everything required to register later **without re-prompting and without regenerating keys**:

```jsonc
// device-bound store key: tetrac:offline:1717459200000  (envelope encrypted under the device key, §7)
{
  "publicKey": "<funds wallet pubkey = identity>",
  "authMethod": "email" | "biometric" | "wallet",
  "email": "<email or internal bio_ identifier>",   // for email/biometric
  "passkeyHash": "<SHA256(passkey)>",               // email/biometric — what the server stores
  "registration": { /* PasskeyRegistration */ },    // biometric only
  "wallets": [ { chain, role, publicKey, encryptedSecret } ],  // the pre-generated bundle
  "createdOfflineAt": 1717459200000,
  "status": "pending"
}
```

**Critical SDK behavior:** reconciliation must register the **already-generated bundle**, not
generate a fresh one. Today `registerWithEmail` always calls `generateWalletBundle()`. Doing that
at reconcile time would orphan the offline keys the user may have already funded. So we need a
register path that **replays a stored bundle**. Good news: the **server already accepts a
client-supplied `wallets[]`** (`server/routes.ts` `register`), so this is a *client-only* change —
add `registerPregenerated({ identity, wallets, ... })` that POSTs the stored bundle as-is.

Per-method notes for reconcile:
- **Email:** POST `register` with `publicKey`, `email`, `passkeyHash`, `wallets`. No re-prompt.
- **Biometric:** same, using the stored internal `bio_…` identifier + `passkeyHash(appKey)` + the
  stored `PasskeyRegistration`.
- **Wallet:** the server's wallet `register` requires a signature over a **server-issued
  challenge** (replay safety) — which can't exist offline. So at reconcile: fetch a fresh
  `challenge`, have the user sign it (local), then `register` with the stored bundle. The
  app key is `SHA256(fixedMessageSig)` and deterministic, so the stored ciphertext stays valid.

---

## 5. Flow C — reconciliation (user-triggered, not polling)

Requirement #5: do **not** poll. Reconcile on a user action (sign-in attempt, app foreground, an
explicit "retry connection" button).

```
user action → ping  GET /api/auth/health   (cheap liveness; add to the route table)
   ├─ down  → stay offline, surface "working offline" state
   └─ up    → for each tetrac:offline:* record:
                POST register(replay stored bundle)        (§4)
                ├─ 201 Created → move record → confirmed cache (tetrac:user:{pk}); status="synced"
                ├─ 409 Exists  → account already registered → switch to LOGIN, IMPORT the offline wallets, then run the MIGRATION FLOW (§11)
                └─ network err → leave pending, try again next action
              then refresh the confirmed cache from GET /api/auth/user-data
```

Reconcile must be **idempotent** — re-running it after a partial success must not double-register or
lose pending records.

---

## 6. Session-state model

Extend the existing three-state model (`client/session.ts` `getAuthStatus`) with an offline state:

| Status | Meaning | Can decrypt/sign? | Server session token? |
|---|---|---|---|
| `authenticated` | token + pubkey + appKey present (online login) | ✅ | ✅ |
| `authenticated_offline` | appKey present + cached blob decrypted; **no** server token | ✅ | ❌ |
| `session_expired` | account known, appKey missing | ❌ (re-auth needed) | — |
| `unauthenticated` | nothing | ❌ | — |

`authenticated_offline` upgrades to `authenticated` automatically on the next successful
reconcile (§5). The app key handling is unchanged: memory + `sessionStorage`, never persisted.

---

## 7. Security model — device-bound cache (mandatory, not raw localStorage)

The offline cache is **never** stored as plain ciphertext in `localStorage`. It is held in a
**device-bound store**: each record (the confirmed cache and every pending offline record) is
wrapped in a second envelope encrypted under a **device key that cannot leave this device**, then
written to IndexedDB. This is a hard requirement of the design, not an optional hardening.

**Why.** If we cached the raw AES bundle, an attacker who can read storage (XSS, malware, a
shared/persistent device) would obtain the **ciphertext + `passkeyHash`** and could mount an
**offline brute-force** at full speed against low-entropy email passkeys (and the co-located,
unsalted `SHA256` `passkeyHash`). Device-binding removes the at-rest payload: an exfiltrated copy of
storage is just an opaque envelope the attacker cannot unwrap off-device.

**Device key — two options (pick per `deviceBinding`):**

| Option | Mechanism | Protects against exfiltration-at-rest | Protects against live in-page XSS | Best for |
|---|---|---|---|---|
| `webauthn-prf` (**recommended**) | Envelope key = the authenticator's **WebAuthn PRF** secret; unwrap requires a user gesture on the device | ✅ | ✅ (attacker can't silently invoke the authenticator) | Biometric users — essentially free; reuses the same credential that already derives their app key |
| `webcrypto` (fallback) | Envelope key = a **non-extractable** `CryptoKey` generated via WebCrypto and kept in IndexedDB | ✅ | ⚠️ partial — a non-extractable key still *unwraps in-page*, so live XSS running in the tab can decrypt; it only stops copy-the-storage exfiltration | Email/wallet users without a PRF-capable authenticator |

Because the envelope key never appears in JS (PRF) or is non-extractable (WebCrypto), copying
`localStorage`/IndexedDB to another machine yields nothing usable.

**Layering.** Two independent locks now guard the secret: (1) the device envelope (this section) and
(2) the per-user app key derived from credentials (§1). An attacker needs *both* the device **and**
the credential. The earlier "weak email passkey" exposure only mattered when the ciphertext was
freely readable — device-binding closes that path.

**Other rules (still required):**
- **App key never persisted.** Unchanged invariant — memory + `sessionStorage` only, re-derived on
  each offline login. The device key wraps the *cache*, never the app key.
- **Offline caching is opt-in** ("Remember this device for offline access"); default off.
- **"Logout" ≠ "forget device."** The device-bound cache survives **logout** (so Flow A re-login
  works) while logout still clears the app key/session. An explicit **"forget this device"** wipes
  the device key and all `tetrac:user:*` / `tetrac:offline:*` records — after which the envelopes are
  permanently undecryptable even if their bytes were copied earlier.
- **Don't store the raw passkey** — only `passkeyHash` (inside the device envelope), or re-prompt at
  reconcile to avoid persisting even the hash.

**Privacy.** Even device-bound, the *presence* of a record reveals "an account was used here." On
shared devices, prefer re-prompt over persistence.

**Residual risk (state honestly).** The `webcrypto` fallback does not stop a live XSS payload
executing in the authenticated tab — it can drive the non-extractable key to unwrap. Only
`webauthn-prf` (user-gesture-gated) defends that case. Treat reveal/offline routes as
security-sensitive (strong CSP, no untrusted third-party scripts) regardless of binding mode.

---

## 8. Storage model

Preserve the current session keys (in `localStorage`/`sessionStorage`); add two namespaces that
live in the **device-bound store** (IndexedDB, each record wrapped under the device key from §7 —
**not raw `localStorage`**). The user's proposed `xyz_offline_<timestamp>` becomes
`tetrac:offline:{timestamp}`.

| Key | Store | Lifetime | Cleared by | Holds |
|---|---|---|---|---|
| `ttc-auth-token`, `ttc-public-key`, `user_email` | localStorage (existing) | existing | `clearSession()` | session pointers (no secrets) |
| `ttc_ek` (app key) | sessionStorage + memory (existing) | session only | logout / tab close | **app key — never persisted, never device-cached** |
| `tetrac:user:{publicKey}` | **device-bound (IndexedDB, §7)** | **persists across logout** (opt-in) | "forget device" | confirmed cache: device-wrapped mirror of `UserData` (ciphertext bundle + `passkeyHash` + `registration`) |
| `tetrac:offline:{timestamp}` | **device-bound (IndexedDB, §7)** | until reconciled | reconcile success / "forget device" | device-wrapped pending offline registration (§4) |
| device key | non-extractable `CryptoKey` in IndexedDB, or WebAuthn PRF (no stored material) | persists | "forget device" | unwraps the two namespaces above |

Logout clears the session (app key + token) but **keeps** the device-bound `tetrac:user:*` records
if the user opted into offline access — that is what enables Flow A after a logout. "Forget device"
destroys the **device key first**, which renders every wrapped record permanently undecryptable, then
wipes the records.

---

## 9. API / component changes (concrete)

**Config** (`core/config.ts`):
```ts
offline?: {
  enabled: boolean;                          // default false (opt-in)
  deviceBinding: "webauthn-prf" | "webcrypto";  // §7 — REQUIRED when enabled; no raw-localStorage mode
  healthPath?: string;                       // default "health"
}
```

**Client** (`src/client/`):
- `deviceKey.ts` — create/load/destroy the device key (WebAuthn PRF or non-extractable WebCrypto);
  `wrap()` / `unwrap()` envelopes.
- `offlineStore.ts` — read/write/wipe the two device-bound namespaces in IndexedDB; always goes
  through `deviceKey` wrap/unwrap. Never touches raw `localStorage`.
- `authClient.ts` — add:
  - `loginOffline({ method, credentials })` → derive key, unwrap + decrypt cache, set offline session.
  - `registerOffline({ method, credentials })` → generate + device-wrap + persist pending record (Flow B).
  - `registerPregenerated({ identity, wallets, passkeyHash?, registration?, signFn? })` → replay a
    stored bundle to the server (Flow C); **no `generateWalletBundle` call**.
  - `reconcile()` → ping health, flush pending, refresh cache (Flow C); idempotent. On 409 →
    `loginThenImport()` + emit a `migration-required` event (§11).
  - `migrateFunds({ from, toFundsWallet, connection })` and `selectSigner({ keep, drop[] })` →
    the operations behind the migration flow (§11).
- `session.ts` — add `authenticated_offline` to `getAuthStatus`; helpers to set/clear offline state.

**React** (`src/react/`):
- `AuthProvider` — on online login, device-wrap + write the confirmed cache; expose offline status.
- `useAuth()` — add `isOffline`, `reconcile()`, and surface `authenticated_offline`.
- `useWalletMigration()` — exposes pending-migration state, per-wallet balances, and the
  `migrateFunds` / `selectSigner` / `exportKey` actions for the migration UI (§11).

**UI** (`src/ui/`, optional package — see `PRD_PRIVY.md` §2):
- `<WalletMigrationModal>` — the migration flow UI (§11): lists wallets, shows balances, lets the
  user pick the funds wallet, sweep funds, select the signer to keep, and export any wallet.

**Server** (`src/server/`, `src/next/`):
- Add a cheap `GET /api/auth/health` to the route table for the liveness ping.
- **No change** to `register` — it already accepts a client `wallets[]` bundle, which Flow C replays.
- **No change** to `import-wallet` — already appends client wallets to `UserData.wallets` (used by §11).
- Add a `delete-wallet` (or `set-wallets`) action so dropped signer wallets can be removed
  server-side after `selectSigner` (today the server only appends; §11 needs removal).

---

## 10. Edge cases & open questions

1. **Same email, two offline devices (Flow B divergence).** Device A and B both offline-register
   for the same email → each generates a *different* funds keypair. Whoever reconciles first wins
   the `email → publicKey` mapping; the second hits **409** at register. **Resolved**: the second
   device does not orphan its keys — it logs in to the existing account, **imports** its
   offline-generated wallets, and runs the **wallet migration flow** so the user consolidates funds
   and picks a signer. See **§11** for the full flow + UI. (Wallet/biometric users don't hit this:
   their identity is the wallet/credential, not a freshly generated funds key.)
2. **Stale cache vs server.** crypto-es AES uses a random salt, so the same plaintext re-encrypts to
   different ciphertext — but it still decrypts correctly. The **server is the source of truth for
   the wallet *set*** (e.g., wallets imported on another device); reconcile should refresh from
   `user-data` and union in any pending offline wallets, not blindly trust the local set.
3. **Clock source.** The `{timestamp}` uses client `Date.now()` — fine; it's only a local
   ordering/label, not a security input.
4. **localStorage quota / eviction.** Bundles are small, but document that storage pressure can
   evict the cache (Safari ITP can clear it after 7 days of inactivity) — offline login then falls
   back to "needs server."
5. **What "logged in" buys offline.** Reads + signing + on-chain submit (RPC is separate). Anything
   that hits *your app's* backend (not the auth server) is out of scope and degrades per the app.

---

## 11. Wallet collision & migration flow

When reconcile (§5) hits a **409** for an offline-registered identity, the offline-generated wallets
are **not discarded and not orphaned**. The SDK logs the user into the existing (winning) account,
**imports** the offline wallets, and the user ends up with **more wallets** than before — then a
guided **migration flow** lets them consolidate. Net rule: *no funds are ever lost; the user
explicitly chooses the surviving funds wallet and signer.*

### 11.1 Resolution steps

```
reconcile() → register → 409 Exists
        │
        ▼
loginWithEmail(existing account)              → online session on the winning identity
        │
        ▼
import-wallet(offline wallets[])              → server appends them; user now has MORE wallets
        │
        ▼
emit "migration-required" → open <WalletMigrationModal>   (§11.2)
```

The imported wallets are tagged (e.g. `origin: "offline-merge"`, carrying their
`createdOfflineAt`) so the UI can label "imported from offline use" vs the account's original
wallets.

### 11.2 Migration UI (required deliverable)

`<WalletMigrationModal>` (in `src/ui/`, driven by `useWalletMigration()`). It must provide:

1. **Wallet list + balance check.** Show every wallet on the account (original + imported), grouped
   by `chain` and `role`. For each, fetch and display the **live balance** (SOL/SPL via the app's
   Solana `connection`; native/ERC-20 via the EVM provider). Balances drive the funds decision.
2. **Funds-wallet migration.** Let the user pick which wallet becomes the **funds** wallet. If the
   non-selected wallet(s) hold a balance, offer **"send funds to selected funds wallet"** — a sweep
   transaction (`migrateFunds`) that transfers the spendable balance (minus fees/rent) from each
   other funds wallet into the chosen one. Show amount, fee estimate, and a confirm step; report
   per-transfer success/failure. Sweeping is **opt-in per source wallet** — never automatic.
3. **Signer-wallet selection.** Let the user choose which `signing` wallet to **keep**. On confirm,
   the **non-selected signer wallet(s) are deleted** (client cache + server via the new
   `delete-wallet` action, §9). Deleting a signer is destructive, so:
   - require explicit confirmation, and
   - **force an export first** (see #4) for any signer being deleted that has ever been used / holds
     a balance, so the user cannot lose a key they still need.
4. **Export option.** Every wallet in the modal has an **Export private key** action
   (`useExportKey` / the safe-reveal pattern from `PRD_PRIVY.md` §2.6 — local decrypt, copy with
   auto-clear, no logging). This is mandatory for any wallet the user is about to drop, and
   available for the rest.

### 11.3 Post-migration state

After the user confirms: one funds wallet per chain (funded), one signer per chain (the kept one),
dropped signers removed server-side and from the device cache, and the confirmed cache
(`tetrac:user:{publicKey}`, §8) re-written (device-wrapped) from the refreshed `user-data`. The
pending `tetrac:offline:*` record is cleared. The migration is **idempotent** — re-opening the
modal after a partial run reflects current on-chain balances and the current wallet set.

### 11.4 Safety rules

- **No silent deletion.** A signer is only removed after explicit selection **and** an export of any
  at-risk key.
- **No silent sweep.** Funds move only on per-wallet confirmation with a shown amount + fee.
- **Failure-safe.** A failed sweep or delete leaves both wallets intact and the migration
  re-runnable; never delete a source before its sweep confirms on-chain.

---

## 12. Recommendation & phasing

1. **Phase 1 — offline login (Flow A) + device-bound store.** Opt-in caching of the confirmed
   bundle, `loginOffline`, `authenticated_offline`, and the §7 device key (ship `webauthn-prf` for
   biometric users, `webcrypto` fallback otherwise). Device-binding is in-scope from day one — there
   is no raw-localStorage interim. Highest value, lowest risk.
2. **Phase 2 — reconcile (Flow C) for existing users.** Health ping + cache refresh. No offline
   registration yet.
3. **Phase 3 — offline registration (Flow B) + pending-queue reconcile + migration flow (§11).**
   Includes `registerPregenerated`, the 409 → import path, the `delete-wallet`/sweep server bits, and
   the `<WalletMigrationModal>` UI. This phase is the one that needs the most product/UX review.

The whole design is consistent with tetrac's self-custody model and preserves the
"app key never persisted" invariant. The cache is **device-bound by mandate** (§7), so caching
ciphertext at rest does not reopen the weak-passkey brute-force path. The remaining product
decisions live in the migration flow (§11): default sweep behavior and how aggressively to force
exports before deleting a signer.
