# PRD — Hotfix: restore re-auth + auto-lock for sensitive key operations

A security-regression hotfix. After the UI/`/ui` migration, signing and **private-key reveal happen
with no re-authentication and no auto-lock** — the new signer/export hooks read the app key straight
from `sessionStorage` and decrypt silently. This restores the controls the original PRD requires.

- **Status:** Draft v1 — **Security regression, high priority**
- **Author:** TTC Engineering
- **Date:** 2026-06-04
- **References:** `docs/PRD.md` §5, §10 (security model); `docs/DRIFTED.md` (root-cause walkthrough); `docs/PRD_PRIVY.md` §2.6–2.7 (the documented trade-off that was over-applied)
- **Constraint:** plan only — no code changes in this document.

---

## 1. Summary of the regression

| | Original PRD intent | Current (drifted) behavior |
|---|---|---|
| Sign a tx | Allowed within an **unlocked window**, then auto-locks (~15s, `AUTO_LOCK_MS`) → re-auth | Silent, forever — app key hot for the tab's lifetime, no lock |
| Reveal / export plaintext key | **Always** a fresh re-auth ceremony ("Re-auth to reveal", home principle #5) | One click, no prompt (`<ExportKeyPanel>` reads the hot app key) |
| Auto-lock + key zeroing | Required (PRD §10.7) | Not ported — no timer, no relock |
| Biometric user expectation | Face ID / Touch ID prompts before a sensitive op | No prompt at all |

The user-visible proof: sign in with biometric → press **Sign message** repeatedly and **Reveal
private key** → no Face ID prompt at any point.

---

## 2. What is and isn't exposed (threat-model clarification)

So the severity is neither overstated nor understated:

- **Plaintext private keys (signing path)** — consumed inside the `withDecryptedKey()` callback and
  not returned, so for *signing* the secret is genuinely transient. This part is fine.
- **Plaintext private keys (reveal/export path)** — **NOT transient.** `useExportKey.reveal()` calls
  `sign(wallet, (s) => s)` — the callback **returns the plaintext out of the envelope**, and the
  hook stores it with `setPlaintext(secret)`. The plaintext private key therefore **sits in React
  state (memory)** for the whole auto-clear window (`autoClearMs`, default **60_000**; the demo
  passes **45_000**) or until **Hide**. JS strings can't be zeroed, so even after `clear()` the
  value lingers in memory until GC. Any script on the page can read it for that entire window.
- **No re-auth gate on reveal.** `useExportKey`'s only guard is `unlocked`, which merely means "the
  app key exists in the session" — true for the full tab lifetime. So **Reveal → Hide → Reveal**
  re-decrypts from the hot app key every time, with **no ceremony, no prompt** (confirmed on `/ui`).
- **App key (`ttc_ek`)** — **persisted in `sessionStorage` + a module-scope memory var for the whole
  tab lifetime.** It can decrypt *every* wallet blob. Any script on the origin (an XSS payload, a
  malicious dependency, a browser extension with page access) can read it and silently decrypt all
  keys. No interaction required.
- **The migration's specific damage:** it did **not** move the app key (sessionStorage was the
  original design, PRD §10.2). It **removed the compensating controls** — the ~15s auto-lock
  (§10.7) and the reveal ceremony — and added a **one-click, repeatable plaintext reveal**
  (`<ExportKeyPanel>`, plaintext held in state) plus **silent signers** (`useSigner` /
  `useSolanaSigner` / `useEvmSigner`). Net effect: the XSS blast radius went from "small window,
  reveal needs interaction" to "entire tab lifetime, zero interaction, repeatable one-click
  plaintext that then lingers in memory."

**Bottom line:** Yes — in the current state an XSS = silent full key compromise, and the reveal flow
additionally parks the plaintext in memory with no gate. The fix is to bound the window (auto-lock),
force a step-up ceremony for the highest-sensitivity action (reveal), and keep the revealed plaintext
lifetime as tight as the runtime allows — exactly as PRD §10 already specifies.

---

## 3. Root cause (from `DRIFTED.md`)

Two layers:

1. **SDK gap.** There is no first-class **lock** concept. `getAppKey()` returns the session key
   forever; `useSigner().sign()`, `useExportKey()`, and `<ExportKeyPanel>` all call
   `withDecryptedKey(wallet, getAppKey(), fn)` with no gate and no timer. PRD §10.7's auto-lock was
   never ported into `src/client/session.ts`.
2. **Demo misuse.** The pre-migration demo enforced re-auth at the **app level** — `unlock()`
   re-derived the app key via a fresh ceremony into a separate `unlockedKey` state, and Show/Hide +
   signing were gated on it. The migration:
   - rewrote `SignMessageCard` to use the silent signer hooks (dropped the `unlockedKey` gate),
   - added `ExportKeyShowcase` (`<ExportKeyPanel>`) directly under the guarded `WalletsPanel`,
   - added another `<ExportKeyPanel>` under `<LoginPanel>` on `/ui`,
   so the demo now *teaches* the ceremony in one card and *bypasses* it in the next.

`DRIFTED.md` is correct that "the SDK cannot force a re-auth on its own" today — that is precisely
the gap this hotfix closes by making lock/unlock a first-class SDK capability.

---

## 4. Target security model (what "fixed" means)

Restate PRD §10 as a tiered operation model the SDK enforces:

| Tier | Operation | Gate |
|---|---|---|
| 0 | Read public keys / status / balances | Always allowed |
| 1 | **Sign** (tx / message) | Allowed **only while unlocked**; the vault auto-locks after `autoLockMs` idle or on tab close. Locked → throws `VaultLockedError` → caller must `unlock()`. |
| 2 | **Reveal / export plaintext** | **Always** a fresh step-up re-auth ceremony, regardless of unlocked state. Never silent. |

**The re-auth ceremony, per method** (this is the prompt the user expected):
- **email** → re-enter passkey → re-derive `PBKDF2(passkey, email)`
- **wallet** → re-sign the fixed app-key message → `SHA256(sig)`
- **biometric** → fresh WebAuthn assertion (PRF) → the Face ID / Touch ID prompt
- Validate every re-derivation by attempting a decrypt of a known blob before accepting it.

Plus the carried-over §10 invariants that must hold after the fix:
- App key never in `localStorage` (still true).
- Decrypted secrets zeroed after use; auto-lock restored (§10.7).
- Deterministic cross-device recovery unchanged (§10.3) — the fix must not break re-derivation.

---

## 5. Proposed SDK changes (spec, not code)

In `src/client/session.ts` + `src/react/*` + `src/ui/ExportKeyPanel.tsx`:

1. **First-class lock state.** Add `locked: boolean` (+ `lockedAt`) to the session and surface it
   on the `AuthProvider` context / `useAuth()` (`isLocked`, `lockedAt`).
2. **Auto-lock timer.** On each successful sensitive op, (re)start an idle timer of `autoLockMs`
   (default **15_000**, per the original `AUTO_LOCK_MS`). On expiry: clear the in-memory app key,
   clear `ttc_ek`, set `locked = true`. Also lock on `visibilitychange`/tab hide (configurable).
3. **`unlock(...)` / `reauth(...)` API.** Re-runs the ceremony for the active method (§4),
   re-derives the app key, validates by decrypt, resets the timer. This is the "SDK can force
   re-auth" capability `DRIFTED.md` says is missing.
4. **Signers throw when locked.** `useSigner().sign()`, `useSolanaSigner`, `useEvmSigner` throw a
   typed `VaultLockedError` when `locked`. No silent decrypt with a stale key.
5. **Reveal always steps up.** `useExportKey()` and `<ExportKeyPanel>` must perform a **fresh
   ceremony per reveal** (default `revealRequiresReauth: true`) — they must not read the hot app key.
   The panel renders a re-auth step (passkey field / "Confirm with Face ID" / "Sign to reveal")
   before the secret is ever decrypted.
6. **Config additions** (`src/core/config.ts`):
   - `autoLockMs` (default `15_000`)
   - `revealRequiresReauth` (default `true`)
   - `appKeyStorage: "session" | "memory"` (default `"session"`; see §6 decision)
   - `lockOnHide` (default `true`)
7. **Zeroing.** Hold decrypted secrets as `Uint8Array` and zero them after the signing/reveal
   callback where the runtime allows (PRD §5 "decrypt-to-sign", §10.7).

These are additive/behavioral; the `useSigner`/`useExportKey` signatures can stay, gaining a
locked-state failure path and (for export) a ceremony step.

---

## 6. Decisions to confirm

1. **App-key storage location.**
   - `session` (default today): survives tab reload → smoother sign UX, but readable by XSS while
     unlocked.
   - `memory`: app key never written to `sessionStorage`; tab reload ⇒ re-auth. Strictly stronger
     against storage-scraping XSS; costs reload persistence.
   - **Recommendation:** keep `session` as default *with auto-lock that actually clears it*, and
     offer `memory` as a high-security opt-in. Reveal always step-ups regardless of mode.
2. **Signing friction.**
   - Per-op prompt (re-auth every signature) — strictest, unusual UX.
   - Unlocked-window + auto-lock — real-wallet UX.
   - **Recommendation:** unlocked-window + auto-lock for signing; **always** step-up for reveal.
3. **Auto-lock duration.** Original was ~15s. 15s may be aggressive for an active signing session.
   - **Recommendation:** default `autoLockMs = 15_000`, configurable; consider a separate, longer
     "active signing" idle window vs an immediate step-up for reveal. Confirm the number.
4. **Home principle #5 ("Re-auth to reveal").** Keep it true (recommended — it's the product's
   core differentiator vs custodial WaaS), rather than `DRIFTED.md`'s option-2 reword. The fix
   makes the claim honest again.

---

## 7. Demo remediation (the three drift sites)

The demo is the live "broken core product" — fix it in lockstep so it stops contradicting the
security story:

- **`DemoShell` → `SignMessageCard`:** gate on `isLocked`; when locked, show "Unlock to sign" and
  route through `unlock()`. Keep the unlocked-window model (don't re-auth every signature).
- **`DemoShell` → `ExportKeyShowcase`:** either remove it, or make its `<ExportKeyPanel>` use the
  new `revealRequiresReauth` step-up so it can't reveal silently beneath the guarded `WalletsPanel`.
- **`/ui` page → `<ExportKeyPanel>`:** must require the ceremony before reveal (or be removed from
  the immediately-post-login surface).
- **`/bridge` page:** embedded signing goes through the locked/unlock model like `DemoShell`.
- Reaffirm **home principle #5** rather than soften it.

---

## 8. Acceptance criteria

- **Biometric reveal prompts.** A biometric user pressing **Reveal private key** triggers a fresh
  Face ID / Touch ID assertion *before* any plaintext appears. (The exact symptom reported.)
- **Auto-lock works.** After `autoLockMs` idle, the vault is `locked`; signing throws
  `VaultLockedError` until `unlock()` succeeds; the lock state is visible in the UI.
- **No silent reveal.** With the vault unlocked *or* locked, `<ExportKeyPanel>` cannot produce
  plaintext without a successful ceremony.
- **XSS blast-radius test.** Locked state (or `memory` mode): `sessionStorage` holds no usable app
  key; a script cannot decrypt a blob without a ceremony. Unlocked window is bounded by `autoLockMs`.
- **No functional regression.** Cross-device deterministic recovery (§10.3), challenge replay
  resistance (§10.5), and all three login flows still pass.
- **Demo is consistent.** All three drift sites gated; home principle #5 holds end-to-end.

---

## 9. Scope & non-goals

- **In scope:** lock/auto-lock, step-up re-auth for reveal, demo gating, config + zeroing.
- **Out of scope:** changing the login methods, wallet generation, storage adapters, or the
  deterministic key-derivation scheme. General XSS prevention (CSP, dependency hygiene) remains the
  consuming app's responsibility — this hotfix only bounds the **blast radius** of key material.

---

## 10. Phasing

| Phase | Deliverable | Why |
|---|---|---|
| **P0 — stop the bleeding (demo)** | Gate/remove the silent `<ExportKeyPanel>` reveals; restore the sign ceremony gate in the demo; reaffirm principle #5 | The live demo currently demonstrates the vulnerability; this needs no SDK release |
| **P1 — SDK lock model** | `isLocked` + `autoLockMs` auto-lock + `unlock()`/`reauth()` + `VaultLockedError` from signers | Closes the "SDK can't force re-auth" gap |
| **P2 — reveal step-up** | `revealRequiresReauth` in `useExportKey()` / `<ExportKeyPanel>` (per-method ceremony) | Restores "Re-auth to reveal" at the SDK level |
| **P3 — hardening** | `appKeyStorage: "memory"` mode, secret zeroing, tests (locked-state, ceremony, XSS smoke) | Strengthens default posture; prevents re-drift |

P0 is shippable immediately and removes the public demonstration of the flaw. P1–P3 land in a
patched SDK release with the §8 acceptance suite gating the merge.
