# Feature PRD — First-class UX in `<LoginPanel>`: hardware-wallet toggle + passkey generator (`0.5.0`)

Move two login-panel affordances that consumers currently **hand-roll on top of** `@tetrac/login-sdk/ui`
into the SDK itself, so they stop reaching around the component with brittle DOM hacks:

1. **A built-in hardware-wallet (Ledger) toggle** rendered directly **beneath the wallet method**, wired to
   the existing `hardwareWallet` hint — the app no longer renders its own checkbox and re-plumbs the flag.
2. **A passkey generator** — a small icon button **inside the email "passkey" input row** that fills the
   field with a crypto-strong secret and reveals it once so the user can save it.

- **Status:** 📝 Proposed. Not yet implemented.
- **Shape:** **Additive UI only.** No wire-protocol change, no crypto change to the auth layer. Adds
  optional props to `LoginPanelProps`, a few `LoginPanelSlot` names, and one self-contained CSPRNG helper.
  Every new field is optional and defaults to today's behaviour → **no breaking change**. The passkey
  generator produces a value the user could already type by hand; it does not alter what gets signed/sent.
- **Driver:** DX + correctness. The point of shipping `@tetrac/login-sdk/ui` is that a consumer can adopt
  `<LoginPanel>` and *not* maintain login UI. But two common needs aren't expressible through the current
  props, so at least one consumer (Shyft) re-implements them **outside** the panel by reaching into the
  SDK's own DOM — coupling to the panel's internal markup, which is exactly what a component contract is
  supposed to prevent.
- **Companion:** [`LEDGER_UI_SUPPORT_PRD.md`](./LEDGER_UI_SUPPORT_PRD.md) already threads the `hardwareWallet`
  **flag** through `WalletMethod` / `connectWallet` / `<ExportKeyPanel>`. This PRD builds on that: the toggle
  in §3.1 is just a **UI producer** for that same flag. It does **not** re-do any flag plumbing or crypto.

---

## 1. Motivation — consumers reach around the component

### 1.1 The hardware-wallet toggle is re-implemented outside the panel

`<LoginPanel>` accepts a `hardwareWallet` **boolean** and threads it to the wallet method
([`LoginPanel.tsx:84,89`](../src/ui/LoginPanel.tsx#L84), [`WalletMethod.tsx:43-47`](../src/ui/WalletMethod.tsx#L43-L47)),
but it renders **no UI to set it**. So a consumer that wants a user-facing "I'm using a Ledger" switch must:

- render its **own** toggle component, hold its **own** `isLedger` state,
- pass that state back in as `hardwareWallet`, and
- **reorder `methods`** to put `wallet` last and position the toggle beneath the panel, because there is no
  way to place content *directly under the wallet button* inside the stack.

That's exactly what Shyft's `src/contexts/LoginContext.tsx` does today (its own switch above/below the panel
+ `methods={["email","biometric","wallet"]}` to force wallet last). The flag works; the **widget and its
placement** are duplicated in every consumer that wants them.

### 1.2 The passkey generator reaches into the SDK's DOM

`EmailMethod` owns the passkey `<input>` and its React state
([`EmailMethod.tsx:25,75-85`](../src/ui/EmailMethod.tsx#L75-L85)). A consumer that wants a "suggest a strong
passkey" button therefore **cannot** add one cleanly — the input is controlled by the SDK's internal
`useState`, with no wrapper, no adornment slot, and no way to set its value.

Shyft works around this by (verified in `src/contexts/LoginContext.tsx` + `src/lib/passkey-gen.ts`):

- `querySelector('input[type="password"]')` **inside the SDK's rendered markup**,
- measuring that input's bounding rect to absolutely-position an overlay button on its right edge, and
- setting the value through the **native `HTMLInputElement.prototype.value` setter** + dispatching a synthetic
  `input` event, because React's controlled input ignores a plain `.value =`.

This is fragile by construction: it couples to the panel's `placeholder`, its single-password-input
assumption, and React's internal event plumbing. Any markup change in `EmailMethod` silently breaks it. The
generator belongs **inside** the method that owns the field.

### 1.3 Why fix it in the SDK

Both features need to sit *between or inside* the panel's own elements (a toggle **under** the wallet button;
a button **inside** the passkey row; a reveal **under** that input). The component owns that DOM, so only the
component can place them without hacks. Shipping them as opt-in props turns two per-consumer workarounds into
one tested, styleable surface — and lets Shyft delete its overlay/measurement/native-setter code.

---

## 2. Goals / Non-goals

### Goals
1. `<LoginPanel>` can render a **hardware-wallet toggle directly beneath the wallet method**, opt-in, wired
   to the same `hardwareWallet` hint `WalletMethod` already consumes — with the wallet method placed last via
   the existing `methods` order (so the toggle lands at the bottom, under "Continue with wallet").
2. The toggle is **accessible** (`role="switch"`, keyboard-operable, label association) and **styleable**
   through new `classNames`/`styles` slots, matching the panel's theming model.
3. `<LoginPanel>` can render a **passkey generator** — an icon-only button inside the passkey input row that
   fills the field with a CSPRNG-strong value and **reveals + offers to copy** it once, with a
   "save this — it can't be recovered" warning.
4. The generator sets the panel's **own** passkey state directly (no DOM hacks, no synthetic events) and is
   **opt-in**, defaulting off.
5. **Zero regression:** every new prop optional; omit them and the panel renders and behaves byte-for-byte as
   today. No change to `core`, `client`, `server`, `react`, or the wire.

### Non-goals
- **Hardware detection.** The toggle only *produces* the `hardwareWallet` boolean the app already owns
  (`LEDGER_UI_SUPPORT_PRD.md` §2 non-goals stand — the SDK never sniffs Ledger). The toggle is the manual
  "user says so" producer of that flag.
- **Changing the passkey KDF / auth flow.** The generator fills the same field the user could type; the
  passkey is still the sole KDF input (`CRYPTO_SPEC.md` §2). No recovery mechanism is added or implied.
- **Password-strength policy / breach checks / entropy meters.** Out of scope; the generator emits a fixed
  high-entropy secret.
- **Persisting the generated passkey.** The SDK never stores it. Revealing it once for the user to save is
  the whole point (§6).

---

## 3. Design — two opt-in, additive props

### 3.1 Built-in hardware-wallet toggle (`hardwareWalletToggle`)

Add an optional prop to `LoginPanelProps` ([`types.ts:58-120`](../src/ui/types.ts#L58-L120)):

```ts
  /**
   * Render a hardware-wallet ("I'm using a Ledger") toggle directly BENEATH the wallet
   * method. Opt-in; omitted → no toggle (today's behaviour). When on, its value becomes the
   * `hardwareWallet` hint for the wallet method (connector-reported value still wins, per
   * WalletMethod). Pass `true` for defaults, or an object to customise copy / initial state.
   *
   * Uncontrolled by default (the panel owns the state). To control it, also pass
   * `hardwareWallet` + `onHardwareWalletChange`.
   */
  hardwareWalletToggle?:
    | boolean
    | { label?: React.ReactNode; description?: React.ReactNode; defaultOn?: boolean };

  /** Controlled toggle: notified whenever the user flips the built-in toggle. */
  onHardwareWalletChange?: (isHardware: boolean) => void;
```

**Behaviour** (in [`LoginPanel.tsx`](../src/ui/LoginPanel.tsx)):

- The panel derives the effective flag: **controlled** when `onHardwareWalletChange` is supplied
  (`hardwareWallet` is the source of truth); otherwise **uncontrolled** with internal state seeded from
  `defaultOn ?? hardwareWallet ?? false`.
- The effective flag is passed to `WalletMethod` as the `hardwareWallet` hint (unchanged plumbing — the
  connector's own report still wins, [`WalletMethod.tsx:45`](../src/ui/WalletMethod.tsx#L45)).
- **Placement:** in the `methods.forEach` loop ([`LoginPanel.tsx:60-113`](../src/ui/LoginPanel.tsx#L60-L113)),
  immediately after pushing the **wallet** node, if `hardwareWalletToggle` is set and the wallet method is
  present, push the toggle node. → The toggle always sits directly under the wallet button; put `wallet` last
  in `methods` and it's at the very bottom. **No content is injected between other methods; no reordering is
  forced on the consumer.** If `wallet` isn't rendered, the toggle isn't either (it only gates that path).
- **Widget:** an accessible switch — a visually-hidden `<input type="checkbox" role="switch">` (keyboard +
  label association) with a track/knob styled off new slots. Default copy: label *"I'm using a Ledger hardware
  wallet"*, description *"You'll approve on the device, and must use the same Ledger to unlock/reveal later."*

New `LoginPanelSlot` names (additive to [`types.ts:37-48`](../src/ui/types.ts#L37-L48)): `toggle`,
`toggleTrack`, `toggleKnob`, `toggleLabel`, `toggleDescription`. Themed via `buildStyles`
([`styles.ts`](../src/ui/styles.ts)) using the existing `appearance.accent` for the on-state.

> This makes Shyft's bespoke switch + `methods` reorder + below-panel placement collapse to:
> `<LoginPanel methods={["email","biometric","wallet"]} hardwareWalletToggle walletConnector={…} />`.

### 3.2 Passkey generator (`passkeyGenerator`)

Add an optional prop to `LoginPanelProps`, threaded into `EmailMethod`:

```ts
  /**
   * Show a "generate a strong passkey" button inside the email passkey input (far right).
   * One click fills the field with a CSPRNG-strong value and reveals it once (with copy)
   * so the user can save it — a generated passkey encrypts the account and CANNOT be
   * recovered. Opt-in; omitted → no button (today's behaviour). Intended for signup/auto
   * (new accounts); see `showFor`.
   */
  passkeyGenerator?:
    | boolean
    | {
        /** Random bytes of entropy (default 24 ≈ 192 bits). */
        bytes?: number;
        /** Icon for the generate button (SDK stays icon-agnostic — pass a lucide node, etc.). */
        icon?: React.ReactNode;
        /** When to show it: "signup" | "auto" | "always". Default follows `emailMode`. */
        showFor?: "signup" | "auto" | "always";
        /** Called with each generated passkey (e.g. so the app can nudge "save this"). */
        onGenerate?: (passkey: string) => void;
      };
```

**Behaviour** (in [`EmailMethod.tsx`](../src/ui/EmailMethod.tsx) — it owns the input + `setPasskey`):

- Wrap the passkey `<input>` ([`:75-85`](../src/ui/EmailMethod.tsx#L75-L85)) in a positioned container and
  render an **icon-only button as a right-aligned adornment** inside it (input gets right padding so text
  never slides under the button). Because the method owns the field, this is plain JSX — **no rect
  measurement, no overlay, no native-setter injection.**
- On click: `const pk = generateStrongPasskey(bytes); setPasskey(pk); reveal(pk); onGenerate?.(pk)`. Setting
  the field is a normal `setPasskey` (it's the same state the input binds to), so the submit button enables
  exactly as if typed.
- **Reveal:** render the value beneath the input (monospace) with a **copy** button and a warning
  *"Save this now — it can't be recovered."* Include a dismiss so it never covers the submit button
  permanently. The reveal is cleared on unmount and is never persisted.
- **Gating:** default visibility follows `emailMode` — shown for `signup`/`auto` (creating an account), hidden
  for `signin` (you type your existing passkey). `showFor: "always"` overrides.

**The generator itself** — a self-contained helper, no new runtime dependency:

```ts
// src/ui/passkey.ts  (or src/client/passkey.ts)
export function generateStrongPasskey(bytes = 24): string {
  const buf = new Uint8Array(Math.max(16, Math.floor(bytes)));
  crypto.getRandomValues(buf);            // WebCrypto CSPRNG — never Math.random
  return encodeUnambiguous(buf);          // base58/base62; alphabet omits 0/O/I/l
}
```

Randomness is the WebCrypto CSPRNG (`crypto.getRandomValues`). Encode to an **unambiguous** alphabet so a
written-down passkey re-types cleanly — base58 is the natural choice (its alphabet already omits `0 O I l`).
The reference consumer (Shyft) uses `bs58`; the SDK can either take that tiny dep or ship a ~15-line internal
base58 encoder to stay dependency-free. Either way the output is a compact ~30-char, ≥128-bit secret.

New `LoginPanelSlot` names (additive): `passkeyField` (the positioned wrapper), `passkeyGenerateButton`,
`passkeyReveal`, `passkeyRevealActions`.

> This makes Shyft's `passkey-gen.ts` + the DOM-measuring overlay in `LoginContext.tsx` disappear in favour of
> `<LoginPanel passkeyGenerator icons={{ … }} />`.

---

## 4. API & type surface

| Area | Change | File |
|---|---|---|
| Panel props | add optional `hardwareWalletToggle?: boolean \| {…}` + `onHardwareWalletChange?` | [`src/ui/types.ts`](../src/ui/types.ts#L58-L120) |
| Panel props | add optional `passkeyGenerator?: boolean \| {…}` | [`src/ui/types.ts`](../src/ui/types.ts#L58-L120) |
| Slots | add `toggle*`, `passkey*` slot names (additive) | [`src/ui/types.ts`](../src/ui/types.ts#L37-L48) |
| Panel render | derive effective HW flag; render toggle node after the wallet node | [`src/ui/LoginPanel.tsx`](../src/ui/LoginPanel.tsx#L60-L113) |
| Email method | passkey-input adornment button + reveal; call `setPasskey` | [`src/ui/EmailMethod.tsx`](../src/ui/EmailMethod.tsx#L75-L85) |
| Styles | default styles for the new slots (accent-driven) | [`src/ui/styles.ts`](../src/ui/styles.ts) |
| Helper | `generateStrongPasskey()` (WebCrypto + unambiguous encoding) | `src/ui/passkey.ts` (new) |
| Exports | re-export any new public types from the ui entry | [`src/ui/index.ts`](../src/ui/index.ts) |

No changes to `src/core`, `src/client` (auth), `src/server`, or `src/react`. No change to `connectWallet`,
`registerWithEmail`, or the message that gets signed.

---

## 5. Backward compatibility

- **Existing `<LoginPanel>` consumers:** compile and render unchanged — `hardwareWalletToggle` and
  `passkeyGenerator` are optional and default to *off*, so a panel that doesn't pass them is byte-identical.
- **Existing `classNames`/`styles` maps:** unaffected; the new slots are only consulted when the new features
  are enabled. Adding slot names to the union is additive.
- **`hardwareWallet` prop:** still works exactly as today; the toggle is a producer for it, not a replacement.
  With no `onHardwareWalletChange`, the panel treats `hardwareWallet` as the toggle's initial value.

---

## 6. Security considerations

- **The toggle adds no trust boundary.** It only sets the existing `hardwareWallet` boolean, which selects
  which *fixed, client-side* app-key message is signed (`LEDGER_UI_SUPPORT_PRD.md` §7, `CRYPTO_SPEC.md`
  §2.2). No challenge/ownership-proof change. The consistency trap (same flag at login + reveal —
  `LEDGER_UI_SUPPORT_PRD.md` §1.3) is unchanged and still the app's responsibility.
- **The passkey generator reveals a secret — intentionally, and only at creation.** The passkey is the sole
  KDF input to the vault (`CRYPTO_SPEC.md` §2); it is **not recoverable**. A generated passkey the user never
  sees = a permanently locked account. So the generator MUST reveal + offer copy + warn. Constraints:
  - **Never persisted by the SDK.** No `localStorage`, no logging, no telemetry — the plaintext lives only in
    React state and the field, and is cleared on unmount.
  - **Shown once, dismissible.** The reveal is transient and can be dismissed; it does not linger after
    submit.
  - **CSPRNG only.** `crypto.getRandomValues` — never `Math.random`. Minimum 128-bit entropy (clamped).
  - **Clipboard is best-effort.** Copy uses `navigator.clipboard` behind the user gesture; failures are
    swallowed (the value is still visible to type/save).
- **No new plaintext exfiltration path.** Unlike `<ExportKeyPanel postToReactNativeWebView>`
  ([`types.ts:176`](../src/ui/types.ts#L176)), the generator never posts the secret anywhere; it only renders
  it for the user.
- **No fresh crypto audit required:** no wire or KDF change. Randomness generation of a user-typable field is
  not a protocol change.

---

## 7. Testing

- **Toggle — flag production:** rendering `<LoginPanel hardwareWalletToggle walletConnector={…} />` and
  flipping the switch drives `connectWallet` with `hardwareWallet: true`; connector-reported value still wins
  when present (regression against `WalletMethod` precedence).
- **Toggle — placement:** with `methods=["email","biometric","wallet"]`, the toggle node renders immediately
  after the wallet node and nowhere else; with no `wallet` in `methods`, no toggle renders.
- **Toggle — controlled vs uncontrolled:** uncontrolled seeds from `defaultOn`/`hardwareWallet`; controlled
  fires `onHardwareWalletChange` and reflects the prop.
- **Toggle — a11y:** the switch is reachable by keyboard, toggles on Space/Enter, and the label is associated.
- **Passkey — fill + enable:** clicking generate sets the passkey field to a ≥16-byte value, enables submit,
  and calls `onGenerate` with the value; the value contains only unambiguous glyphs (no `0 O I l`) and is
  unique across many draws (real CSPRNG).
- **Passkey — reveal lifecycle:** the reveal appears with copy + warning, dismisses, and clears on unmount;
  the SDK writes nothing to storage (spy on `localStorage`).
- **Passkey — gating:** hidden for `emailMode="signin"`, shown for `signup`/`auto`, overridable by `showFor`.
- **Regression:** default `<LoginPanel>` (no new props) snapshot/behaviour unchanged; `tsc --noEmit` +
  Prettier clean; full Jest suite green.

---

## 8. Rollout

1. **Ship §3.1** (toggle) and **§3.2** (passkey generator) together as an additive UI minor — `0.5.0`.
2. **Docs:** add a `<LoginPanel>` usage example to `README.md` showing both props; cross-link
   `LEDGER_UI_SUPPORT_PRD.md` §3.3 (the flag the toggle drives).
3. **Consumer follow-up:** Shyft retires its bespoke toggle + `passkey-gen.ts` + the DOM-measuring passkey
   overlay in `src/contexts/LoginContext.tsx`, switching to `hardwareWalletToggle` + `passkeyGenerator`.
   next-ttc / ttc.box can adopt the same props instead of re-implementing.

---

## 9. Open questions

1. **base58 dependency vs in-house encoder.** Take a `bs58` dep (as Shyft does) or ship a small internal
   unambiguous encoder to keep `@tetrac/login-sdk/ui` dependency-light? Recommend the in-house encoder — the
   ui package should stay lean, and base58 is trivial.
2. **Toggle default placement when `wallet` is *not* last.** If a consumer orders `wallet` in the middle, the
   toggle still renders directly under it (correct — it belongs to the wallet method). Confirm we do **not**
   also add a "force wallet last" convenience (the existing `methods` order already covers it).
3. **Passkey reveal default.** Should the reveal be shown automatically on generate (proposed) or only behind
   an explicit "show" affordance? Auto-reveal is safer against silent lockout; confirm.
4. **Copy-clear timing.** `<ExportKeyPanel>` clears the clipboard after `clipboardClearMs`
   ([`types.ts:158-163`](../src/ui/types.ts#L158-L163)). Should the generator reuse that convention for the
   copied passkey? Likely yes, for consistency.

---

> Companion reads: [`LEDGER_UI_SUPPORT_PRD.md`](./LEDGER_UI_SUPPORT_PRD.md) (the `hardwareWallet` flag this
> toggle drives), [`LEDGER_SUPPORT_PRD.md`](./LEDGER_SUPPORT_PRD.md) (the auth/crypto layer), and
> `docs/CRYPTO_SPEC.md` §2 (the passkey is the KDF input — hence "no recovery"). Reference consumer
> workarounds this PRD retires: Shyft `src/contexts/LoginContext.tsx` + `src/lib/passkey-gen.ts`. If this PRD
> and the code ever disagree once implemented, the code is correct and this document is the bug.
