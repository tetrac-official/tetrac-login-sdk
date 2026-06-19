# Feature PRD — optional session→User-Agent binding (`bindSessionToUserAgent`)

Add an opt-in hardening that **pins a session to the client's `User-Agent`**: when enabled, a session
records `SHA-256(User-Agent)` at issue time and rejects any later request whose UA hash differs (or is
absent). It raises the bar for replaying a stolen bearer token from a different client — a coarse,
defense-in-depth speed bump, not a device-identity control.

- **Status:** ✅ Shipped in `0.3.2` (commit `a2d9936`). This file documents the delivered design.
- **Source finding:** WI-23 (`audits/v0.3.2-PRD.md`), from Audit B "Auth-3" in `audits/agent-ai.md`.
- **Shape:** additive, **default off**, no new dependencies, no breaking change.

---

## 1. Motivation — the gap this closes

Audit B claimed sessions "lack revocation & cryptographic randomness" and "persist indefinitely." Against
the actual code, those are **false**:

- Tokens are 256-bit CSPRNG (`generateSessionToken` → `randomHex(32)`, `src/core/crypto.ts`).
- TTL is 4h by default and **single-active-session** — each login revokes the prior token
  (`issueSession`, `src/server/session.ts`).
- `logout()` revokes server-side via `POST /logout` (`src/server/routes.ts`).

The one **genuine** residual the finding points at is that a session is bound only to `(token, publicKey)`
— there is no binding to the client it was issued to. A stolen token works from anywhere. UA binding is a
small, optional step that closes part of that gap without changing the session model.

### Why no `/revoke` endpoint

Audit B also suggested "implement `/revoke`." We deliberately did **not** add one: with single-active-session
there is only ever one token per user, and `POST /logout` already revokes the presented (i.e. the only)
token. A `/revoke` of that token would be a verbatim duplicate of `/logout`, and there are no "other"
sessions to revoke. The additive value is UA binding, which is what shipped.

---

## 2. Design

### 2.1 Flag

`AuthConfig.bindSessionToUserAgent: boolean` (**default `false`**, `src/core/config.ts`). When off, behavior
is byte-for-byte unchanged.

### 2.2 Fingerprint

```
fingerprint = SHA-256(utf8(userAgent))   // hex; hashUserAgent() in src/core/crypto.ts
```

`hashUserAgent(ua)` returns `undefined` for a missing/empty UA, so the caller skips binding rather than
pinning a session to the empty string. SHA-256 is the same `@noble/hashes` primitive already used elsewhere
— **no new dependency**.

### 2.3 Session value encoding (no storage-shape change when off)

The session store value is normally just the owner's `publicKey`. When a fingerprint is present it becomes
`publicKey|fingerprint`. Wallet public keys (base58 / `0x`-hex / hex) never contain `|`, so the split is
unambiguous (`src/server/session.ts`):

```
issue:   value = fingerprint ? `${publicKey}|${fingerprint}` : publicKey
verify:  [owner, storedFp] = split(value, "|")
```

When the flag is off, no fingerprint is passed, the value stays the bare `publicKey`, and existing sessions
and the `session:{token} -> publicKey` shape are untouched.

### 2.4 Issue vs verify (the key asymmetry)

- **Issue time** (`issueSession(storage, user, config, fingerprint?)`): the caller passes a fingerprint
  **only when the flag is on** (`issueFingerprint(req)` in `routes.ts`).
- **Verify time** (`verifySession(storage, token, publicKey, config, presentedFingerprint?)`): the caller
  **always** computes the request UA hash (`reqFingerprint(req)`); `verifySession` enforces it **iff a
  fingerprint was stored** on that session, comparing with `timingSafeEqual`.

This means enforcement is **per-session**, keyed on whether the session was bound — so turning the flag off
later never silently un-binds sessions that are already live; they stay enforced until they expire.

```ts
// src/server/session.ts (verify)
const { publicKey: owner, fingerprint: storedFp } = decodeSessionValue(value);
if (owner !== publicKey) return null;
if (storedFp && (!presentedFingerprint || !timingSafeEqual(storedFp, presentedFingerprint))) return null;
```

### 2.5 Wiring

`routes.ts` threads the fingerprint through the **4 issue sites** (`register`, `login`, `loginWallet`,
`connectWallet`) and the **3 verify sites** (`logout`, `userData`, `importWallet`). The UA is read from
`req.headers.get("user-agent")`.

**No client change.** Browsers attach `User-Agent` to same-origin `fetch` automatically, so the existing
`AuthClient` flows carry it for free; non-browser callers that omit it simply don't get bound.

---

## 3. Cryptography & storage

- **Hash:** SHA-256 (`@noble/hashes`), hex. **Compare:** constant-time `timingSafeEqual` (`src/core/crypto.ts`).
- **Storage:** the existing `session:{token}` key; value is `publicKey` (off) or `publicKey|fingerprint`
  (on). Same TTL (`sessionTtlSeconds`). No new keys, no `UserData` field, no server endpoint.
- **No new dependency.**

---

## 4. Lifecycle & edge cases

| Event | Behavior |
|---|---|
| Flag off (default) | Stored value is the bare `publicKey`; UA ignored; identical to pre-0.3.2 |
| Flag on, matching UA | Verifies normally |
| Flag on, different UA | `verifySession` → null → 401 |
| Flag on, request has no UA | Fails closed (401) — a bound session requires a presented UA |
| Browser/app update changes the UA | Session invalidated → user must re-login (documented trade-off) |
| Flag turned off after sessions were bound | Bound sessions stay enforced until they expire (per-session) |
| `logout` with a non-matching UA | `verifySession` returns null so nothing is revoked, but logout still returns `{ ok: true }` (non-leaking); the token dies at its TTL |

---

## 5. Security model & threats

- **Raises the cost of stolen-token reuse** from a different client (extension, copied token, different
  device) — the attacker must also reproduce the exact `User-Agent`.
- **Explicitly NOT a control:** the UA is attacker-spoofable and is not a device identity. Treat it as a
  speed bump layered on top of CSPRNG tokens + short TTL + single-active-session + revoke-on-login.
- **No reduction of existing guarantees:** tokens, TTL, and revocation semantics are unchanged; the app key
  is still memory-only and never involved here.
- **Default off** so deployments opt in knowingly, accepting the re-login-on-UA-change trade-off.

---

## 6. Testing

`tests/session-fingerprint.test.ts` (5 cases):

- **off (default):** stored value is the bare `publicKey`; a different UA still verifies.
- **on:** stored value equals `${publicKey}|${hashUserAgent(UA)}`; the matching UA verifies.
- **on:** a different UA is rejected (401).
- **on:** a request with no UA is rejected (401).
- **per-session:** a session bound while the flag was on stays enforced (matching UA ok, different UA 401)
  even when checked by a handler with the flag now **off**.

Project rule honored: tests use only ephemeral/synthetic keys.

---

## 7. Files touched

| File | Change |
|---|---|
| `src/core/config.ts` | `bindSessionToUserAgent: boolean` (interface + `DEFAULT_CONFIG`, default false) |
| `src/core/crypto.ts` | `hashUserAgent(ua): string \| undefined` |
| `src/server/session.ts` | `encodeSessionValue`/`decodeSessionValue`; fingerprint params on `issueSession`/`verifySession`; constant-time compare |
| `src/server/routes.ts` | `issueFingerprint`/`reqFingerprint`; threaded into 4 issue + 3 verify sites |
| `tests/session-fingerprint.test.ts` | new suite |
| `README.md`, `docs/CRYPTO_SPEC.md` §5.2 | documentation |

---

## 8. Non-goals

- Not a device-identity or anti-fraud control (UA is spoofable).
- No multi-session model and no `/revoke` endpoint (single-active-session + `/logout` already cover it).
- No `UserData` field, no new server endpoint, no client/browser changes.
- Not on by default.

---

## 9. Acceptance criteria (all met)

- [x] `bindSessionToUserAgent` defaults false; off behavior is unchanged (bare-`publicKey` value, UA ignored).
- [x] On: sessions store `publicKey|SHA-256(UA)`; a matching UA verifies, a different/missing UA is rejected.
- [x] Enforcement is per-session — disabling the flag never un-binds live sessions.
- [x] Constant-time fingerprint comparison; no new dependency; no storage-shape change when off.
- [x] Additive, non-breaking; `npm run format:check` + `typecheck` + `test` (179) + `build` green.
