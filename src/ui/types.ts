// Public types for the optional UI package (`@tetrac/login-sdk/ui`).
// Kept separate from the headless `@tetrac/login-sdk/react` surface so apps that
// build their own UI never pull these in.
import type { CSSProperties } from "react";
import type { AuthMethod, AuthResult } from "../core/types.js";
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
