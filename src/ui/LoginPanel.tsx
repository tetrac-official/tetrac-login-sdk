// Optional, themeable login UI. The PRD §2.2 calls for a tree-shakeable
// `@tetrac/login-sdk/ui` entry that closes the "headless gap" without forcing a
// UI on apps that want their own. This is the v0.1 skeleton: it composes three
// independent method sub-panels and forwards results to the host app.
//
// Apps that don't import from `@tetrac/login-sdk/ui` pay nothing for it — the
// core `@tetrac/login-sdk/react` surface stays untouched.
import React, { useCallback, useId, useMemo, useState, type CSSProperties } from "react";
import { EmailMethod } from "./EmailMethod.js";
import { WalletMethod } from "./WalletMethod.js";
import { BiometricMethod } from "./BiometricMethod.js";
import { buildStyles } from "./styles.js";
import type { HardwareWalletToggleConfig, LoginMethod, LoginPanelProps, LoginPanelSlot } from "./types.js";

const DEFAULT_METHODS: LoginMethod[] = ["email", "wallet", "biometric"];

export function LoginPanel(props: LoginPanelProps) {
  const {
    methods = DEFAULT_METHODS,
    emailMode = "auto",
    onSuccess,
    onError,
    walletConnector,
    hardwareWallet,
    hardwareWalletToggle,
    onHardwareWalletChange,
    passkeyGenerator,
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

  // --- 0.5.0: hardware-wallet toggle state ---
  // CONTROLLED when `onHardwareWalletChange` is supplied (the parent owns the flag
  // via `hardwareWallet`); otherwise UNCONTROLLED with internal state seeded once
  // (lazy initializer) from `defaultOn ?? hardwareWallet ?? false`. Reading the
  // seed once means a later `hardwareWallet` prop change never clobbers an
  // uncontrolled user's toggle.
  const toggleConfig: HardwareWalletToggleConfig =
    hardwareWalletToggle && typeof hardwareWalletToggle === "object" ? hardwareWalletToggle : {};
  const isControlled = typeof onHardwareWalletChange === "function";
  const [uncontrolledOn, setUncontrolledOn] = useState<boolean>(
    () => toggleConfig.defaultOn ?? hardwareWallet ?? false,
  );
  const toggleOn = isControlled ? (hardwareWallet ?? false) : uncontrolledOn;

  const handleToggle = useCallback(
    (next: boolean) => {
      if (!isControlled) setUncontrolledOn(next);
      onHardwareWalletChange?.(next);
    },
    [isControlled, onHardwareWalletChange],
  );

  // The toggle only renders when opted in AND a wallet button will render (needs a
  // connector). When the feature is OFF, `effectiveHardwareWallet` is exactly the
  // raw `hardwareWallet` prop — today's behaviour, byte-identical.
  const showToggle = Boolean(hardwareWalletToggle) && Boolean(walletConnector);
  const effectiveHardwareWallet = hardwareWalletToggle ? toggleOn : hardwareWallet;

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
          passkeyGenerator={passkeyGenerator}
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
            hardwareWallet={effectiveHardwareWallet}
            icon={icons?.wallet}
            styles={styles}
            classNames={classNames}
            onSuccess={handleSuccess("wallet")}
            onError={handleError("wallet")}
          />,
        );
        // 0.5.0: the hardware-wallet toggle renders DIRECTLY under the wallet
        // button, in-loop, only when opted in AND a connector exists (this `else`
        // branch). No reordering / "force wallet last" convenience.
        if (showToggle) {
          nodes.push(
            <HardwareWalletToggle
              key="hardware-wallet-toggle"
              on={toggleOn}
              onChange={handleToggle}
              config={toggleConfig}
              styles={styles}
              classNames={classNames}
              accent={appearance?.accent ?? "#111111"}
            />,
          );
        }
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

const DEFAULT_HW_LABEL = "I'm using a Ledger hardware wallet";
const DEFAULT_HW_DESCRIPTION =
  "You'll approve on the device, and must use the same Ledger to unlock/reveal later.";

// Standard SR-only recipe: hides the native checkbox visually while keeping it
// focusable + operable + in the a11y tree. Do NOT use display:none / hidden —
// those remove it from the tab order and the a11y tree.
const VISUALLY_HIDDEN: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0 0 0 0)",
  whiteSpace: "nowrap",
  border: 0,
};

/**
 * The hardware-wallet toggle, an accessible switch. The REAL control is a
 * visually-hidden native `<input type="checkbox" role="switch">` wrapped in a
 * `<label>` — so keyboard, `aria-checked`, and the label association all come
 * for free. The visible track/knob spans are decorative and `aria-hidden`.
 *
 * a11y notes:
 *  - Keyboard: a native checkbox toggles on Space natively; applying
 *    `role="switch"` opts into the ARIA switch pattern, whose contract expects
 *    BOTH Space and Enter. So we add an `onKeyDown` that toggles on Enter
 *    (Space stays native) to honour that contract.
 *  - Accessible name: when `label` is a string it is the accessible name; for a
 *    ReactNode label the caller can pass `ariaLabel` so the announced name
 *    tracks the visible copy instead of the generic "Hardware wallet".
 *  - Accessible description: the caveat text is wired via `aria-describedby`
 *    (only when a description is present) so a screen reader announces it.
 */
function HardwareWalletToggle(props: {
  on: boolean;
  onChange: (next: boolean) => void;
  config: HardwareWalletToggleConfig;
  styles: Record<LoginPanelSlot, CSSProperties>;
  classNames?: LoginPanelProps["classNames"];
  accent: string;
}) {
  const { on, onChange, config, styles, classNames, accent } = props;
  const [focused, setFocused] = useState(false);
  const descId = useId();

  const label = config.label ?? DEFAULT_HW_LABEL;
  const description = config.description === undefined ? DEFAULT_HW_DESCRIPTION : config.description;
  const hasDescription = description !== null && description !== undefined;
  // String label → use it verbatim as the accessible name. Non-string (ReactNode)
  // label → honour an explicit `ariaLabel`, else fall back to the generic name.
  const ariaLabel = typeof label === "string" ? label : (config.ariaLabel ?? "Hardware wallet");

  const trackStyle: CSSProperties = {
    ...styles.toggleTrack,
    ...(on ? { background: accent } : null),
    ...(focused ? { boxShadow: `0 0 0 3px ${accent}33` } : null),
  };
  const knobStyle: CSSProperties = {
    ...styles.toggleKnob,
    // 44w track, 20w knob, 3px inset → off:left 3, on:+18px translate.
    ...(on ? { transform: "translateX(18px)" } : null),
  };

  return (
    <label className={classNames?.toggle} style={styles.toggle}>
      <input
        type="checkbox"
        role="switch"
        aria-checked={on}
        aria-label={ariaLabel}
        aria-describedby={hasDescription ? descId : undefined}
        checked={on}
        onChange={(e) => onChange(e.target.checked)}
        // Space toggles a checkbox natively; role="switch" additionally implies
        // Enter, which a native checkbox does NOT handle — so wire it up here.
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            onChange(!on);
          }
        }}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        style={VISUALLY_HIDDEN}
      />
      <span className={classNames?.toggleTrack} style={trackStyle} aria-hidden="true">
        <span className={classNames?.toggleKnob} style={knobStyle} />
      </span>
      <span style={{ display: "flex", flexDirection: "column" }}>
        <span className={classNames?.toggleLabel} style={styles.toggleLabel}>
          {label}
        </span>
        {hasDescription ? (
          <span id={descId} className={classNames?.toggleDescription} style={styles.toggleDescription}>
            {description}
          </span>
        ) : null}
      </span>
    </label>
  );
}
