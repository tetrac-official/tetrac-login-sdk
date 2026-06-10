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
  | "muted";

/** Minimal appearance tokens. The skeleton intentionally ships just two. */
export interface LoginPanelAppearance {
  /** Accent colour for primary buttons. */
  accent?: string;
  /** Border radius (px) applied to inputs / buttons. */
  radius?: number;
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
