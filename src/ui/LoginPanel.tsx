// Optional, themeable login UI. The PRD §2.2 calls for a tree-shakeable
// `@tetrac/login-sdk/ui` entry that closes the "headless gap" without forcing a
// UI on apps that want their own. This is the v0.1 skeleton: it composes three
// independent method sub-panels and forwards results to the host app.
//
// Apps that don't import from `@tetrac/login-sdk/ui` pay nothing for it — the
// core `@tetrac/login-sdk/react` surface stays untouched.
import React, { useMemo, type CSSProperties } from "react";
import { EmailMethod } from "./EmailMethod.js";
import { WalletMethod } from "./WalletMethod.js";
import { BiometricMethod } from "./BiometricMethod.js";
import { buildStyles } from "./styles.js";
import type { LoginMethod, LoginPanelProps, LoginPanelSlot } from "./types.js";

const DEFAULT_METHODS: LoginMethod[] = ["email", "wallet", "biometric"];

export function LoginPanel(props: LoginPanelProps) {
  const {
    methods = DEFAULT_METHODS,
    emailMode = "auto",
    onSuccess,
    onError,
    walletConnector,
    hardwareWallet,
    passkeyRegistration,
    onPasskeyRegistered,
    biometricUserName = "tetrac-user",
    icons,
    title = "Log in or sign up",
    className,
    classNames,
    styles: stylesOverride,
    appearance,
  } = props;

  // Memoise the style table so re-renders don't churn inline objects. Per-slot
  // overrides are merged on top of the defaults so callers can tweak a single
  // slot (e.g. just `input`) without copying the rest.
  const styles = useMemo(() => {
    const base = buildStyles(appearance);
    if (!stylesOverride) return base;
    const merged: Record<LoginPanelSlot, CSSProperties> = { ...base };
    (Object.keys(stylesOverride) as LoginPanelSlot[]).forEach((slot) => {
      merged[slot] = { ...base[slot], ...stylesOverride[slot] };
    });
    return merged;
  }, [appearance, stylesOverride]);

  const handleSuccess = (method: LoginMethod) => (result: Parameters<NonNullable<typeof onSuccess>>[0]) => {
    onSuccess?.(result, method);
  };
  const handleError = (method: LoginMethod) => (err: Error) => {
    onError?.(err, method);
  };

  // Render methods in the order requested; each panel manages its own state and
  // surfaces its own errors inline. No dividers between methods — the new design
  // is a clean stack of icon buttons.
  const nodes: React.ReactNode[] = [];
  methods.forEach((m) => {
    if (m === "email") {
      nodes.push(
        <EmailMethod
          key="email"
          mode={emailMode}
          icon={icons?.email}
          styles={styles}
          classNames={classNames}
          onSuccess={handleSuccess("email")}
          onError={handleError("email")}
        />,
      );
    } else if (m === "wallet") {
      if (!walletConnector) {
        // No connector → render a stub that tells the developer what's missing
        // instead of silently dropping the method.
        nodes.push(
          <div key="wallet" className={classNames?.method} style={styles.method}>
            <span className={classNames?.muted} style={styles.muted}>
              Pass a `walletConnector` prop to enable wallet sign-in.
            </span>
          </div>,
        );
      } else {
        nodes.push(
          <WalletMethod
            key="wallet"
            connector={walletConnector}
            hardwareWallet={hardwareWallet}
            icon={icons?.wallet}
            styles={styles}
            classNames={classNames}
            onSuccess={handleSuccess("wallet")}
            onError={handleError("wallet")}
          />,
        );
      }
    } else if (m === "biometric") {
      nodes.push(
        <BiometricMethod
          key="biometric"
          registration={passkeyRegistration ?? null}
          userName={biometricUserName}
          icon={icons?.biometric}
          styles={styles}
          classNames={classNames}
          onSuccess={handleSuccess("biometric")}
          onError={handleError("biometric")}
          onRegistered={onPasskeyRegistered}
        />,
      );
    }
  });

  return (
    <div className={[className, classNames?.root].filter(Boolean).join(" ") || undefined} style={styles.root}>
      {title !== null ? (
        <h2 className={classNames?.title} style={styles.title}>
          {title}
        </h2>
      ) : null}
      {nodes}
    </div>
  );
}
