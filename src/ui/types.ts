// Public types for the optional UI package (`@tetrac/login-sdk/ui`).
// Kept separate from the headless `@tetrac/login-sdk/react` surface so apps that
// build their own UI never pull these in.
import type { CSSProperties } from "react";
import type { AuthMethod, AuthResult, EncryptedWallet } from "../core/types.js";
import type { PasskeyRegistration } from "../client/webauthn.js";

/** The methods a <LoginPanel> can render. Mirrors core AuthMethod 1:1. */
export type LoginMethod = AuthMethod;

/**
 * Glue an app passes in so the SDK can drive a Web3 wallet without taking a
 * dependency on `@solana/wallet-adapter-react` (or any specific wallet lib).
 * `connect()` is expected to open the host app's wallet selector, return once
 * the user has approved, and yield the two things the SDK needs to sign in:
 * the public key and a `signMessage` function.
 */
export interface WalletConnector {
  connect: () => Promise<{
    publicKey: string;
    signMessage: (message: Uint8Array) => Promise<Uint8Array>;
    /**
     * True when the connected account is hardware-backed (e.g. a Ledger behind
     * Phantom). Selects the newline-free, clear-signable app-key message and the
     * off-chain-envelope key derivation. The app determines this (probe / adapter
     * signal / user toggle); the SDK does not detect it. MUST be the same value
     * the app later passes to <ExportKeyPanel> / reauthenticate for this account,
     * or the reveal derives a different key and fails with "wrong credentials".
     */
    hardwareWallet?: boolean;
  }>;
  /** Optional label override, e.g. "Continue with Phantom". */
  label?: string;
}

/** Slot names for `classNames` overrides. Stable surface — additive only. */
export type LoginPanelSlot =
  | "root"
  | "title"
  | "method"
  | "methodLabel"
  | "input"
  | "button"
  | "primaryButton"
  | "iconWrap"
  | "error"
  | "divider"
  | "muted"
  // --- 0.5.0 additive: hardware-wallet toggle ---
  | "toggle"
  | "toggleTrack"
  | "toggleKnob"
  | "toggleLabel"
  | "toggleDescription"
  // --- 0.5.0 additive: passkey generator ---
  | "passkeyField"
  | "passkeyGenerateButton"
  | "passkeyReveal"
  | "passkeyRevealActions";

/** Minimal appearance tokens. The skeleton intentionally ships just two. */
export interface LoginPanelAppearance {
  /** Accent colour for primary buttons. */
  accent?: string;
  /** Border radius (px) applied to inputs / buttons. */
  radius?: number;
}

/** Object form of `hardwareWalletToggle` — customise copy / initial state. */
export interface HardwareWalletToggleConfig {
  /** Switch label. Default: "I'm using a Ledger hardware wallet". */
  label?: React.ReactNode;
  /**
   * Accessible name for the switch. Only consulted when `label` is NOT a string
   * (e.g. a ReactNode with an icon), so the announced name can track the custom
   * visible label instead of the generic "Hardware wallet" fallback. When `label`
   * is a string it is used verbatim as the accessible name and this is ignored.
   */
  ariaLabel?: string;
  /**
   * Helper text under the label. Default explains the reveal-consistency rule
   * ("...must use the same Ledger to unlock/reveal later."). Pass `null` to omit.
   * When present it is wired to the switch via `aria-describedby` so screen
   * readers announce the caveat.
   */
  description?: React.ReactNode;
  /**
   * Initial on-state for the UNCONTROLLED toggle only (no `onHardwareWalletChange`).
   * Ignored when controlled. Seeds from `defaultOn ?? hardwareWallet ?? false`.
   */
  defaultOn?: boolean;
}

/** When the passkey generator button is shown, relative to `emailMode`. */
export type PasskeyGeneratorShowFor = "signup" | "auto" | "always";

/** Object form of `passkeyGenerator`. */
export interface PasskeyGeneratorConfig {
  /**
   * Random bytes of entropy. Default 24 (~192-bit). Clamped to a MINIMUM of 16
   * bytes (128-bit) — smaller values are raised to 16, never honoured as-is.
   */
  bytes?: number;
  /** Icon node for the generate button (SDK stays icon-agnostic). */
  icon?: React.ReactNode;
  /**
   * When to show the button. Default follows `emailMode`: shown for signup/auto,
   * hidden for signin. `"always"` overrides (shows even in signin).
   */
  showFor?: PasskeyGeneratorShowFor;
  /** Called with each generated passkey (e.g. to nudge "save this"). */
  onGenerate?: (passkey: string) => void;
}

export interface LoginPanelProps {
  /** Which methods to render, in order. Defaults to all three. */
  methods?: LoginMethod[];
  /**
   * Email-method behaviour:
   *   - "auto"   → try register, fall back to login on 409 (the recommended default)
   *   - "signin" → only call loginWithEmail
   *   - "signup" → only call registerWithEmail
   */
  emailMode?: "auto" | "signin" | "signup";

  /** Fired once any method completes successfully. */
  onSuccess?: (result: AuthResult, method: LoginMethod) => void;
  /** Fired for any thrown error; the panel still surfaces it inline. */
  onError?: (err: Error, method: LoginMethod) => void;

  /** Required to render the "wallet" method — see `WalletConnector`. */
  walletConnector?: WalletConnector;

  /**
   * Default hardware-wallet hint for the wallet method. The connector's own
   * `hardwareWallet` (if it returns one) wins; this is the fallback. Defaults to
   * false. Pass `true` on a hardware-focused surface to avoid a detection
   * round-trip. Whatever value ultimately drives login MUST match the value
   * passed to <ExportKeyPanel hardwareWallet> for the same account (see §1.3).
   */
  hardwareWallet?: boolean;

  /**
   * Render a hardware-wallet ("I'm using a Ledger") toggle directly BENEATH the
   * wallet method. Opt-in; omitted → no toggle (byte-identical to today). When on,
   * its value becomes the `hardwareWallet` hint for the wallet method (the
   * connector's own report still wins, per WalletMethod). Pass `true` for
   * defaults, or an object to customise copy / initial state.
   *
   * UNCONTROLLED by default (the panel owns the state, seeded from `defaultOn ??
   * hardwareWallet ?? false`). To CONTROL it, also pass `onHardwareWalletChange` —
   * then `hardwareWallet` is the source of truth and the panel holds no internal
   * toggle state.
   *
   * Only renders when the `wallet` method is present AND a `walletConnector` is
   * supplied; otherwise no toggle (it belongs to the wallet method).
   */
  hardwareWalletToggle?: boolean | HardwareWalletToggleConfig;

  /**
   * Controlled toggle callback. Supplying this makes the built-in toggle
   * CONTROLLED: `hardwareWallet` becomes the source of truth and this fires on
   * every flip. Omit it for the default uncontrolled behaviour.
   */
  onHardwareWalletChange?: (isHardware: boolean) => void;

  /**
   * Show a "generate a strong passkey" icon button inside the email passkey input
   * (far right). One click fills the field with a CSPRNG-strong value and
   * AUTO-REVEALS it once (with copy) so the user can save it — a generated passkey
   * encrypts the account and CANNOT be recovered. Opt-in; omitted → no button
   * (today's behaviour). Never persisted by the SDK; the reveal clears on unmount.
   *
   * Gating: default follows `emailMode` — shown for signup/auto, hidden for
   * signin. `showFor: "always"` overrides.
   */
  passkeyGenerator?: boolean | PasskeyGeneratorConfig;

  /**
   * Optional icon rendered inside each method's button, keyed by method. The SDK
   * stays icon-library-agnostic (just like it is wallet-library-agnostic): pass
   * your own nodes, e.g. lucide-react — `{ email: <Mail />, wallet: <Wallet />,
   * biometric: <Fingerprint /> }`.
   */
  icons?: Partial<Record<LoginMethod, React.ReactNode>>;

  /**
   * Existing biometric registration, if the app has one cached (localStorage,
   * IndexedDB, …). When present, the biometric method renders an "Unlock"
   * button instead of "Enable".
   */
  passkeyRegistration?: PasskeyRegistration | null;
  /** Called after a fresh biometric registration so the app can persist it. */
  onPasskeyRegistered?: (registration: PasskeyRegistration) => void;
  /** Label shown to the authenticator at registration time. */
  biometricUserName?: string;

  /** Optional heading. Pass `null` to hide. */
  title?: React.ReactNode;
  /** Class on the outer container. */
  className?: string;
  /** Per-slot class overrides for fine-grained styling. */
  classNames?: Partial<Record<LoginPanelSlot, string>>;
  /**
   * Per-slot inline style overrides. Merged over the defaults so callers can
   * change just what they need (e.g. dark-theme the inputs without rewriting
   * the whole table). Inline styles always win over `classNames`, so use this
   * when you need to defeat the defaults from a CSS-modules / Tailwind setup.
   */
  styles?: Partial<Record<LoginPanelSlot, CSSProperties>>;
  /** Minimal theme tokens applied to the default inline styles. */
  appearance?: LoginPanelAppearance;
}

/** Slot names for <ExportKeyPanel> overrides. */
export type ExportKeyPanelSlot =
  | "root"
  | "title"
  | "description"
  | "input"
  | "button"
  | "primaryButton"
  | "secretBlock"
  | "actions"
  | "error"
  | "muted";

/** Optional copy overrides for i18n / branding. */
export interface ExportKeyPanelLabels {
  reveal?: string;
  copy?: string;
  copied?: string;
  hide?: string;
  warning?: string;
  cleared?: string;
}

export interface ExportKeyPanelProps {
  /**
   * The wallet whose private key to reveal. Pass null/undefined to render the
   * panel in a disabled state (e.g. while user-data is still loading).
   */
  wallet: EncryptedWallet | null | undefined;

  /**
   * Drop the revealed plaintext from state after this many ms. Set to 0 to
   * disable. Default 60_000.
   */
  autoClearMs?: number;

  /**
   * After copying to the clipboard, write an empty string back this many ms
   * later (best-effort — works only while the page stays focused). Set to 0
   * to disable. Default 30_000.
   */
  clipboardClearMs?: number;

  /**
   * When the host page is a React Native WebView, post the result back via
   * `window.ReactNativeWebView.postMessage(...)`. Matches the contract Privy's
   * hosted reveal flow uses.
   *
   * Default **false**. This posts the revealed *plaintext* private key to the
   * host shell (`window.ReactNativeWebView`), so it must only be enabled when
   * the panel is rendered inside a trusted RN WebView you control (e.g. Shyft).
   * Leaving it off means a generic web consumer never exfiltrates the key to an
   * ambient host bridge; RN hosts opt in explicitly by setting this `true`.
   */
  postToReactNativeWebView?: boolean;

  /** Optional heading. Pass null to hide. */
  title?: React.ReactNode;
  /** Description / warning text shown above the reveal button. */
  description?: React.ReactNode;

  /**
   * Reveal ALWAYS requires a fresh re-auth ceremony. For a **biometric** account
   * the panel needs the stored registration to run the WebAuthn assertion; pass
   * it here (the app persists it after registerWithBiometric).
   */
  passkeyRegistration?: PasskeyRegistration | null;
  /**
   * For a **wallet** account, the panel needs to re-sign the fixed app-key
   * message to re-derive the key. Provide the connected wallet's signMessage.
   */
  walletSignMessage?: (message: Uint8Array) => Promise<Uint8Array>;
  /**
   * For a hardware-backed **wallet** account, re-derive the reveal key from the
   * newline-free message. MUST match the value used at login for this account,
   * or the reveal derives a different key and fails with "wrong credentials".
   */
  hardwareWallet?: boolean;

  /** Class on the outer container. */
  className?: string;
  classNames?: Partial<Record<ExportKeyPanelSlot, string>>;
  styles?: Partial<Record<ExportKeyPanelSlot, CSSProperties>>;
  /** Reuses LoginPanelAppearance tokens (accent + radius) for visual cohesion. */
  appearance?: LoginPanelAppearance;
  labels?: ExportKeyPanelLabels;

  /** Fired after a successful reveal. */
  onReveal?: (plaintext: string) => void;
  /** Fired on any error during reveal. */
  onError?: (err: Error) => void;
}
