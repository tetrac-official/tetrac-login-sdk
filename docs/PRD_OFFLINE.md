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
load cached bundle from localStorage  (tetrac:user:{publicKey})
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
  ("encryption keys never in localStorage") is preserved. Offline login re-derives it each time.
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
// localStorage key: tetrac:offline:1717459200000
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
                ├─ 409 Exists  → account already registered → switch to LOGIN, then RECONCILE WALLETS (§9 edge case)
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

## 7. Security analysis — the central trade-off (read carefully)

Persisting the ciphertext bundle in `localStorage` **changes the threat model** and is the part of
this design that most needs sign-off.

**What changes.** Today the blob lives only on the server, so brute-forcing a weak passkey requires
hitting the rate-limited backend, and the attacker must first compromise the server. With local
caching, an attacker who can read `localStorage` (XSS, malware, a shared/persistent device) gets
the **ciphertext + `passkeyHash`** and can mount an **offline brute-force / dictionary attack** at
full speed against:
- email users with a weak `passkey` (PBKDF2 is the only cost), and
- the co-located `passkeyHash` (unsalted `SHA256` — even cheaper to test).

Wallet-derived keys (`SHA256(256-bit signature)`) are not brute-forceable; biometric keys depend on
the authenticator. The exposure is concentrated on **low-entropy email passkeys.**

**Mitigations (recommended, in priority order):**
1. **Device-bind the cache envelope.** Don't store raw ciphertext+hash. Wrap the whole offline
   record under a **device key** — a non-extractable WebCrypto key (kept in IndexedDB) or, best,
   the **WebAuthn PRF secret**. Then mere `localStorage` exfiltration is useless without the
   authenticator/device. For biometric users this is essentially free and very strong.
2. **Raise PBKDF2 iterations** for email users when offline caching is enabled (config-driven;
   default is 100k in `core/config.ts`).
3. **Make offline caching opt-in** ("Remember this device for offline access"). Default off.
4. **Separate "logout" from "forget device."** Per requirement, the cache survives **logout** (so
   offline re-login is possible) — but logout must still clear the app key/session. Add an explicit
   **"forget this device"** that wipes all `tetrac:user:*` / `tetrac:offline:*` records. Never
   leave the cache on a device the user signed out of *and* wanted forgotten.
5. **Don't store the raw passkey** — only `passkeyHash` (already non-reversible), or re-prompt at
   reconcile to avoid persisting even the hash.

**Privacy.** A persisted cache reveals "an account was used on this device" to anyone who inspects
storage. On shared devices, prefer re-prompt over persistence, or device-bind (mitigation 1).

**Preserved invariant.** The app/encryption key is **never** written to `localStorage` in any flow
— it remains memory + `sessionStorage`, re-derived on each offline login.

---

## 8. Storage model

Preserve the current session keys; add two namespaces. (The user's proposed
`xyz_offline_<timestamp>` becomes `tetrac:offline:{timestamp}`.)

| Key | Lifetime | Cleared by | Holds |
|---|---|---|---|
| `ttc-auth-token`, `ttc-public-key`, `user_email` | existing | `clearSession()` | session pointers |
| `ttc_ek` (app key) | existing — session only | logout / tab close | **app key (never persisted to localStorage)** |
| `tetrac:user:{publicKey}` | **persists across logout** (opt-in) | "forget device" | confirmed cache: mirror of `UserData` (ciphertext bundle + `passkeyHash` + `registration`) |
| `tetrac:offline:{timestamp}` | until reconciled | reconcile success / "forget device" | pending offline registration (§4) |

Logout clears the session (app key + token) but **keeps** `tetrac:user:*` if the user opted into
offline access — that is what enables Flow A after a logout. "Forget device" wipes both new
namespaces.

---

## 9. API / component changes (concrete)

**Config** (`core/config.ts`):
```ts
offline?: {
  enabled: boolean;                       // default false (opt-in)
  cache: "local" | "memory";             // where the blob lives
  deviceBinding?: "none" | "webcrypto" | "webauthn-prf";  // §7 mitigation 1
  healthPath?: string;                   // default "health"
}
```

**Client** (`src/client/`):
- `offlineStore.ts` — read/write/wipe the two namespaces; optional device-binding wrap.
- `authClient.ts` — add:
  - `loginOffline({ method, credentials })` → derive key, decrypt cache, set offline session.
  - `registerOffline({ method, credentials })` → generate+persist pending record (Flow B).
  - `registerPregenerated({ identity, wallets, passkeyHash?, registration?, signFn? })` → replay a
    stored bundle to the server (Flow C); **no `generateWalletBundle` call**.
  - `reconcile()` → ping health, flush pending, refresh cache (Flow C); idempotent.
- `session.ts` — add `authenticated_offline` to `getAuthStatus`; helpers to set/clear offline state.

**React** (`src/react/`):
- `AuthProvider` — on online login, write the confirmed cache; expose offline status.
- `useAuth()` — add `isOffline`, `reconcile()`, and surface `authenticated_offline`.

**Server** (`src/server/`, `src/next/`):
- Add a cheap `GET /api/auth/health` to the route table for the liveness ping.
- **No change** to `register` — it already accepts a client `wallets[]` bundle, which is exactly
  what Flow C replays.

---

## 10. Edge cases & open questions

1. **Same email, two offline devices (Flow B divergence).** Device A and B both offline-register
   for the same email → each generates a *different* funds keypair. Whoever reconciles first wins
   the `email → publicKey` mapping; the second hits **409** at register. The second device's
   offline-generated (possibly already-funded) wallet would be **orphaned**. This is the thorniest
   correctness hazard. Options on 409: (a) login as the existing account and **`import-wallet`** the
   orphan as an extra wallet (server already supports `import-wallet`), surfacing "you have funds in
   a second wallet"; (b) warn and let the user export the orphan key. **Open decision** — pick a
   default. Wallet/biometric users don't have this issue the same way (identity is the wallet/credential).
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

## 11. Recommendation & phasing

1. **Phase 1 — offline login (Flow A).** Add opt-in local caching of the confirmed bundle +
   `loginOffline` + `authenticated_offline`. Highest value, lowest risk. Ship device-binding
   (§7.1) in the same phase for email users, since that's where the brute-force exposure is.
2. **Phase 2 — reconcile (Flow C) for existing users.** Health ping + cache refresh. No offline
   registration yet.
3. **Phase 3 — offline registration (Flow B) + pending-queue reconcile.** Includes the
   `registerPregenerated` path and the 409/divergence handling (§10.1) — gate this phase on a
   decision for that edge case.

The whole design is consistent with tetrac's self-custody model and preserves the
"app key never persisted" invariant. The one genuine trade-off requiring explicit sign-off is
caching ciphertext at rest (§7); device-binding the cache is the recommended way to take that on
without materially weakening weak-passkey email users.
