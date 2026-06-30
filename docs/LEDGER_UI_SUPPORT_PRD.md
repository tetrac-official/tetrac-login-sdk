# Feature PRD — Hardware-wallet (`hardwareWallet`) support in the official UI (`0.4.5`)

Thread the existing `hardwareWallet` flag through the optional UI package
(`@tetrac/login-sdk/ui`) so that **Ledger-backed accounts can log in *and* reveal keys through the
stock `<LoginPanel>` / `<ExportKeyPanel>`**, not just through a hand-rolled headless integration.

The auth + crypto layer for hardware wallets already shipped (the `hardwareWallet` flag on
`connectWallet` / `loginWithWallet` / `registerWithWallet` / `ReauthCredentials`, plus off-chain-envelope
verification — see [`LEDGER_SUPPORT_PRD.md`](./LEDGER_SUPPORT_PRD.md)). But the **UI layer was never
updated to pass that flag**, so a consumer using the official components silently logs a Ledger user in
with the *software* app-key message and then can't decrypt their vault. This PRD closes that one gap.

- **Status:** 📝 Proposed. Not yet implemented.
- **Shape:** **Purely additive UI plumbing.** No wire-protocol change, no crypto change. Extends one
  return type (`WalletConnector.connect()`) and one props type (`ExportKeyPanelProps`) with an optional
  `hardwareWallet` field, and threads it into the two `connectWallet` / `reveal` call sites that currently
  drop it. Every new field is optional and defaults to today's behaviour → **no breaking change**, no
  security-surface change (the flag already exists in core and only selects which fixed message is signed).
- **Driver:** Product/DX — a consumer (next-ttc, Shyft, ttc.box) that adopts the official `<LoginPanel>`
  to avoid maintaining its own auth UI **cannot** support hardware wallets through it, even though the
  underlying SDK supports them. Today they must drop down to the headless `useAuth()` API and re-implement
  the panel (which is exactly what next-ttc did) — defeating the purpose of shipping a UI package.
- **Reproduction (verified 2026-06-30, next-ttc + a real Ledger via Phantom):** render
  `<LoginPanel methods={["wallet"]} walletConnector={…} />` with a Phantom-injected connector whose active
  account is Ledger-backed → sign in → **"session armed" (login succeeds)** → then `<ExportKeyPanel
  walletSignMessage={…} />` reveal → **`Re-authentication failed — wrong credentials`**. Login passes
  (server verifies the off-chain envelope), but the panel derived the app key from the *software* message
  while the account's wallets were keyed with the *hardware* message → decrypt mismatch. This is the
  "login works but the embedded blob never decrypts" failure called out in
  [`LEDGER_SUPPORT_PRD.md`](./LEDGER_SUPPORT_PRD.md) §1.3 and the skill's "Common mistakes" table.
- **Verification (planned):** unit tests that the flag flows connector → `connectWallet` and panel →
  `reveal`; a login-HW-then-reveal-HW round-trip that decrypts; a login-HW-then-reveal-SW guard that
  *must* fail; software-path byte-stable; `tsc --noEmit` + Prettier clean; full Jest suite green.

---

## 1. Motivation — the UI silently drops `hardwareWallet`

The headless API is correct. The UI throws the flag away.

### 1.1 Login path — `WalletMethod` / `WalletConnector`

The connector contract yields only `{ publicKey, signMessage }`
([`src/ui/types.ts:18-25`](../src/ui/types.ts#L18-L25)):

```ts
export interface WalletConnector {
  connect: () => Promise<{
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
  }>;
  label?: string;
}
```

`WalletMethod` then calls `connectWallet` **without** `hardwareWallet`
([`src/ui/WalletMethod.tsx:29-31`](../src/ui/WalletMethod.tsx#L29-L31)):

```ts
const { publicKey, signMessage } = await connector.connect();
// connectWallet = register if new, login if known — one round trip.
const result = await connectWallet({ publicKey, signMessage });   // ← hardwareWallet defaults to false
```

But `connectWallet` (and `loginWithWallet` / `registerWithWallet`) **accept** `hardwareWallet`
([`src/react/useAuth.ts:60,67,74`](../src/react/useAuth.ts#L60), used at
[`src/client/authClient.ts:268,275`](../src/client/authClient.ts#L268) to pick the app-key message). So a
Ledger account is keyed/derived with the software (newline-bearing) message form regardless of what it is.

### 1.2 Reveal path — `ExportKeyPanel`

Same omission. The panel takes a `walletSignMessage` but no companion flag
([`src/ui/types.ts:175`](../src/ui/types.ts#L175)), and reveals without it
([`src/ui/ExportKeyPanel.tsx:177`](../src/ui/ExportKeyPanel.tsx#L177)):

```tsx
onClick={() => walletSignMessage && doReveal({ signMessage: walletSignMessage })}  // ← no hardwareWallet
```

`ReauthCredentials`'s wallet variant accepts `hardwareWallet`
([`src/client/authClient.ts:51`](../src/client/authClient.ts#L51), consumed at
[`:125`](../src/client/authClient.ts#L125) to choose the key message), so the panel is the only thing in
the way.

### 1.3 Why this is worse than a plain "unsupported" — the consistency trap

`hardwareWallet` must be **identical** at register, login, `reauthenticate`, and reveal, or the app key
re-derives differently and decryption fails silently (`LEDGER_SUPPORT_PRD.md` §4.1; `CRYPTO_SPEC.md`
§2.2). Because the UI hard-codes `false` everywhere, a hardware-keyed account:

- **logs in "successfully"** (the server tries all signature encodings, so the off-chain ownership proof
  passes — see `LEDGER_SUPPORT_PRD.md` §3.2), then
- **fails every key operation** (reveal / unlock / sign) with `wrong credentials`, because the derived key
  ≠ the key the wallets were encrypted under.

A false-positive login that produces an unusable vault is a worse user experience than an honest "hardware
wallets aren't supported in this component." The flag exists precisely to prevent this; the UI just isn't
passing it.

---

## 2. Goals / Non-goals

### Goals
1. A consumer can drive a **hardware-wallet login** through the stock `<LoginPanel>` by having its
   `WalletConnector.connect()` report `hardwareWallet: true`.
2. A consumer can drive a **hardware-wallet reveal** through the stock `<ExportKeyPanel>` by passing
   `hardwareWallet` alongside `walletSignMessage`.
3. The flag flows to the **same** core calls the headless API already uses, so login and reveal derive the
   **same** app key (closes the §1.3 trap).
4. **Zero regression** for software-wallet, email, and biometric flows — every new field optional,
   defaulting to today's exact behaviour and bytes.
5. The SDK stays **wallet-library-agnostic**: it does not detect hardware itself; the consuming app decides
   (probe / adapter signal / user toggle) and reports the boolean, exactly as it already supplies
   `signMessage`.

### Non-goals
- The auth/crypto correctness work (off-chain verification, envelope-drift-safe key wrapping, recovery
  factor). That is [`LEDGER_SUPPORT_PRD.md`](./LEDGER_SUPPORT_PRD.md)'s scope. This PRD assumes that layer
  and only exposes its existing `hardwareWallet` switch through the UI.
- **In-SDK hardware detection.** No probe, no `@solana/wallet-adapter` dependency, no `isLedger` sniffing
  inside `@tetrac/login-sdk/ui`. Detection is the app's job (see §6).
- Native WebHID/WebUSB transport, EVM hardware wallets, or any change to ciphertext format — all out of
  scope and unchanged.

---

## 3. Design — additive flag plumbing

### 3.1 `WalletConnector` reports the encoding it used

Extend the `connect()` result with an optional `hardwareWallet` ([`src/ui/types.ts`](../src/ui/types.ts)):

```ts
export interface WalletConnector {
  connect: () => Promise<{
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
    /**
     * True when the connected account is hardware-backed (e.g. a Ledger behind
     * Phantom). Selects the newline-free, clear-signable app-key message and the
     * off-chain-envelope key derivation. The app determines this (probe / adapter
     * signal / user toggle); the SDK does not detect it. MUST be the same value
     * the app later passes to <ExportKeyPanel> / reauthenticate for this account.
     */
    hardwareWallet?: boolean;
  }>;
  label?: string;
}
```

`WalletMethod` threads it through ([`src/ui/WalletMethod.tsx:29-31`](../src/ui/WalletMethod.tsx#L29-L31)):

```ts
const { publicKey, signMessage, hardwareWallet } = await connector.connect();
const result = await connectWallet({ publicKey, signMessage, hardwareWallet });
```

`hardwareWallet` is optional → an existing connector that returns only `{ publicKey, signMessage }` yields
`undefined` → `connectWallet` defaults to `false` → **byte-identical to today**.

### 3.2 `<ExportKeyPanel>` accepts the matching flag

Add an optional prop ([`src/ui/types.ts` `ExportKeyPanelProps`](../src/ui/types.ts#L127-L189)):

```ts
  /**
   * For a hardware-backed **wallet** account, re-derive the reveal key from the
   * newline-free message. MUST match the value used at login for this account,
   * or the reveal derives a different key and fails with "wrong credentials".
   */
  hardwareWallet?: boolean;
```

Thread it into the wallet reveal ([`src/ui/ExportKeyPanel.tsx:177`](../src/ui/ExportKeyPanel.tsx#L177)):

```tsx
onClick={() =>
  walletSignMessage && doReveal({ signMessage: walletSignMessage, hardwareWallet })
}
```

### 3.3 (Recommended) a `<LoginPanel>` convenience prop

For apps that already know the account is hardware before the connector runs (e.g. a Ledger-focused page),
add an optional pass-through on `LoginPanelProps`
([`src/ui/types.ts:49-102`](../src/ui/types.ts#L49-L102)):

```ts
  /**
   * Default hardware-wallet hint for the wallet method. The connector's own
   * `hardwareWallet` (if it returns one) wins; this is the fallback. Defaults to
   * false. Pass `true` on a hardware-focused surface to avoid a detection round-trip.
   */
  hardwareWallet?: boolean;
```

`LoginPanel` forwards it to `WalletMethod`, which uses `connectResult.hardwareWallet ?? props.hardwareWallet
?? false`. Optional and additive; omit it and nothing changes. (If we want the smallest possible surface,
§3.3 can be deferred — §3.1 + §3.2 alone fully fix the reproduction.)

---

## 4. API & type surface

| Area | Change | File |
|---|---|---|
| Connector result | add optional `hardwareWallet?: boolean` to `WalletConnector.connect()`'s return | [`src/ui/types.ts`](../src/ui/types.ts#L18-L25) |
| Login method | destructure + forward `hardwareWallet` into `connectWallet(...)` | [`src/ui/WalletMethod.tsx`](../src/ui/WalletMethod.tsx#L29-L31) |
| Reveal props | add optional `hardwareWallet?: boolean` to `ExportKeyPanelProps` | [`src/ui/types.ts`](../src/ui/types.ts#L127-L189) |
| Reveal method | forward `hardwareWallet` into `doReveal({ signMessage, hardwareWallet })` | [`src/ui/ExportKeyPanel.tsx`](../src/ui/ExportKeyPanel.tsx#L177) |
| Login panel (opt.) | add optional `hardwareWallet?: boolean` pass-through prop | [`src/ui/types.ts`](../src/ui/types.ts#L49-L102), [`src/ui/LoginPanel.tsx`](../src/ui/LoginPanel.tsx) |
| Docs | integrator note: detection is the app's job; pass the SAME flag at login + reveal | [`README.md`](../README.md) |

No changes to `src/core`, `src/client`, `src/server`, or `src/react` — they already accept the flag.

---

## 5. Backward compatibility

- **Software wallets / email / biometric:** unaffected. New fields are optional; absent → `false`/today's
  path. No behavioural or byte change.
- **Existing consumers of `<LoginPanel>` / `<ExportKeyPanel>`:** compile unchanged — a connector returning
  only `{ publicKey, signMessage }` and a panel without `hardwareWallet` behave exactly as now.
- **Type compatibility:** widening a `Promise<{...}>` return with an *optional* property and adding an
  *optional* prop are both non-breaking under structural typing.

---

## 6. Consumer guidance (the part that prevents misuse)

The SDK exposes the switch; the app owns detection and consistency. Document the contract:

1. **Detect once, per account.** Recognise hardware via a probe (sign a short ASCII string and check
   whether it verifies against the raw bytes vs the off-chain envelope — `offchainMessageCandidates` from
   `@tetrac/login-sdk/ledger`), a wallet-adapter signal (`adapter.name === "Ledger"`), or an explicit user
   toggle. Persist the result keyed by public key.
2. **Report it consistently.** Return the *same* `hardwareWallet` from `WalletConnector.connect()` and pass
   the *same* value to `<ExportKeyPanel hardwareWallet>` and to any `reauthenticate({ signMessage,
   hardwareWallet })`. A mismatch silently breaks decryption (§1.3).

> Reference implementation: next-ttc's `src/utils/auth/walletHardware.ts` (`resolveWalletHardwareFlag` —
> persisted flag → direct-Ledger adapter → false) and its `/testing/login` harness, which drove the §1
> reproduction.

---

## 7. Security considerations

- **No new trust boundary.** `hardwareWallet` only selects which *fixed, client-side* app-key message gets
  signed; it does not touch the challenge/ownership proof (`LEDGER_SUPPORT_PRD.md` §3, `CRYPTO_SPEC.md`
  §5.1). The verifier is unchanged. The UI is merely no longer discarding a value the core already trusts.
- **No secret handling added.** Both call sites already pass a `signMessage`; this adds a boolean beside it.
  No plaintext, no key material, nothing logged.
- **Failure mode improves.** Today's silent false-positive login → unusable vault becomes a correct login +
  working reveal when the flag is supplied (or unchanged when it isn't).
- No fresh audit required: this PRD ships **no** crypto or wire change. (The crypto audit belongs to
  `LEDGER_SUPPORT_PRD.md` §9.)

---

## 8. Testing

- **Unit — flow:** a `WalletConnector` returning `hardwareWallet: true` ⇒ `connectWallet` is called with
  `hardwareWallet: true`; `<ExportKeyPanel hardwareWallet>` ⇒ `reveal` receives `{ signMessage,
  hardwareWallet: true }`. Mock `useAuth`/`useExportKey` and assert the args.
- **Unit — default:** a connector returning only `{ publicKey, signMessage }` ⇒ `connectWallet` arg has
  `hardwareWallet` undefined/false (regression guard for the software path).
- **Integration — round-trip (the bug):** register/login a HW account through `<LoginPanel>` with
  `hardwareWallet: true`, then reveal through `<ExportKeyPanel hardwareWallet>` ⇒ **decrypts**. Same login,
  reveal with `hardwareWallet` omitted/false ⇒ **fails** (locks in the §1.3 consistency requirement).
- **Regression:** existing UI snapshot/behaviour tests for software-wallet login + reveal stay green;
  `tsc --noEmit` + Prettier clean; full Jest suite green.
- **Manual:** the next-ttc `/testing/login` harness flips from "session armed → reveal: wrong credentials"
  to "session armed → reveal: decrypted ✓" once the connector reports `hardwareWallet: true`.

---

## 9. Rollout

1. **Ship §3.1 + §3.2** (connector return field + `WalletMethod` thread; `ExportKeyPanelProps` field +
   reveal thread). This alone fixes the reproduction. Patch/minor (`0.4.5`).
2. **Optionally ship §3.3** (`LoginPanel` convenience prop) in the same release.
3. **Docs:** add an integrator note to `README.md` and cross-link `LEDGER_SUPPORT_PRD.md` §6 (consumer
   guidance) ↔ this PRD §6.
4. **Consumer follow-up:** next-ttc can then retire its bespoke `AuthSection` wallet plumbing in favour of
   `<LoginPanel hardwareWallet>` if desired (optional — its current dashboard path already works).

---

## 10. Open questions

1. **Connector-returns vs panel-prop precedence.** Recommend the connector's value wins (it reflects the
   account actually connected this session) and the `LoginPanel`/per-call prop is the fallback. Confirm.
2. **Should `<ExportKeyPanel>` accept a `WalletConnector` instead of a raw `walletSignMessage` + flag**, so
   the hardware bit and the signer travel together and can't be passed inconsistently? Cleaner contract,
   slightly larger change — decide vs the minimal `hardwareWallet` prop in §3.2.
3. **Unlock UI.** There is no stock unlock/`reauthenticate` panel today (only `<LoginPanel>` +
   `<ExportKeyPanel>`). If one is added later, it must take `hardwareWallet` from day one (§1.3).

---

> Companion reads: [`LEDGER_SUPPORT_PRD.md`](./LEDGER_SUPPORT_PRD.md) (the auth + crypto layer this PRD
> surfaces), `docs/CRYPTO_SPEC.md` §2.2, and `docs/THREAT_MODEL.md`. If this PRD and the code ever disagree
> once implemented, the code is correct and this document is the bug.
