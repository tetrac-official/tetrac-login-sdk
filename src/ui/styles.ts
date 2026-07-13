// Default inline styles for the UI skeleton.
//
// We intentionally do not ship a CSS file: every style here can be replaced by
// passing `classNames={{ root: "...", button: "..." }}` to <LoginPanel>. The
// goal is "looks reasonable out of the box, fully overridable".
import type { CSSProperties } from "react";
import type { ExportKeyPanelSlot, LoginPanelAppearance, LoginPanelSlot } from "./types.js";

// Taller controls + more rounded corners are the new default look.
const DEFAULT_RADIUS = 14;
const DEFAULT_ACCENT = "#111111";

export function buildStyles(appearance?: LoginPanelAppearance): Record<LoginPanelSlot, CSSProperties> {
  const radius = appearance?.radius ?? DEFAULT_RADIUS;
  // `accent` is kept for API stability but the new design uses one flat colour
  // for every button (no gradient, no primary/secondary split). The 0.5.0
  // hardware-wallet toggle applies `appearance.accent` to its ON-state track
  // inline in LoginPanel (state-dependent), so buildStyles still ignores it here.
  void (appearance?.accent ?? DEFAULT_ACCENT);

  const baseInput: CSSProperties = {
    width: "100%",
    padding: "16px 16px", // taller inputs
    borderRadius: radius,
    border: "1px solid #d4d4d8",
    fontSize: 15,
    outline: "none",
    boxSizing: "border-box",
  };

  // One shared button style: same background as the panel (transparent) + border,
  // tall enough for comfortable mobile tapping, rounded, with a left-aligned row
  // so the bordered icon sits on the left and the (bold) label follows it.
  const baseButton: CSSProperties = {
    width: "100%",
    padding: "16px 16px", // taller — mobile touch-friendly
    borderRadius: radius,
    border: "1px solid #d4d4d8",
    background: "transparent", // inherit the panel's background colour
    color: "#111111",
    fontSize: 15,
    fontWeight: 600, // heavier label text
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "flex-start", // icon + label sit on the left
    gap: 12, // ~2x — more breathing room between the icon box and label
  };

  return {
    root: {
      display: "flex",
      flexDirection: "column",
      gap: 12,
      maxWidth: 360,
      padding: "0 4px", // +4px breathing room on each side
      boxSizing: "border-box",
      fontFamily:
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      color: "#111111",
    },
    // Extra gap below the heading so it sits further from the first button.
    title: { fontSize: 22, fontWeight: 700, margin: "0 0 12px", textAlign: "center" },
    method: { display: "flex", flexDirection: "column", gap: 10 },
    // Method labels are no longer rendered by the panel; the slot remains for
    // back-compat / custom layouts.
    methodLabel: { fontSize: 12, color: "#52525b", textTransform: "uppercase", letterSpacing: 0.4 },
    input: baseInput,
    button: baseButton,
    // Same colour as every other button — the gradient/primary fill is gone.
    primaryButton: { ...baseButton },
    // Bordered box around the per-method icon, pinned to the button's left.
    iconWrap: {
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      width: 34,
      height: 34,
      borderRadius: Math.max(8, radius - 4),
      border: "1px solid #d4d4d8",
      flexShrink: 0,
    },
    error: { color: "#b91c1c", fontSize: 13 },
    divider: { border: "none", borderTop: "1px solid #e4e4e7", margin: 0 },
    muted: { color: "#71717a", fontSize: 13 },

    // --- 0.5.0: hardware-wallet toggle (accessible switch) ---
    // Row: [track+knob] [label / description column]. Sits directly under the
    // wallet button inside the method stack.
    toggle: {
      display: "flex",
      alignItems: "flex-start",
      gap: 12,
      padding: "4px 2px",
      cursor: "pointer",
      userSelect: "none",
    },
    // The visible switch body. `background` here is the OFF colour; the ON colour
    // (appearance.accent) is applied inline in LoginPanel (state-dependent).
    toggleTrack: {
      position: "relative",
      flexShrink: 0,
      width: 44,
      height: 26,
      borderRadius: 999,
      background: "#d4d4d8",
      transition: "background 120ms ease",
      boxSizing: "border-box",
      marginTop: 2,
    },
    // The sliding knob. The on-transform (translateX) is applied inline.
    toggleKnob: {
      position: "absolute",
      top: 3,
      left: 3,
      width: 20,
      height: 20,
      borderRadius: 999,
      background: "#ffffff",
      boxShadow: "0 1px 2px rgba(0,0,0,0.2)",
      transition: "transform 120ms ease",
    },
    toggleLabel: { fontSize: 14, fontWeight: 600, color: "#111111", lineHeight: 1.3 },
    toggleDescription: { fontSize: 12, color: "#71717a", lineHeight: 1.4, marginTop: 2 },

    // --- 0.5.0: passkey generator ---
    // Positioned wrapper around the passkey <input> so the generate button can be
    // an absolutely-positioned right adornment. `position: relative` is the
    // load-bearing bit; the input inside gets right padding inline so typed text
    // never slides under the button. This wrapper is only rendered when the
    // generator is active — the no-generator render stays byte-identical.
    passkeyField: { position: "relative", display: "block", width: "100%" },
    passkeyGenerateButton: {
      position: "absolute",
      top: "50%",
      right: 8,
      transform: "translateY(-50%)",
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      width: 32,
      height: 32,
      padding: 0,
      borderRadius: Math.max(8, radius - 6),
      border: "1px solid #d4d4d8",
      background: "#ffffff",
      color: "#111111",
      cursor: "pointer",
      fontSize: 14,
      lineHeight: 1,
    },
    // The one-time reveal block under the input — monospace secret + warning.
    // Amber, mirrors ExportKeyPanel.secretBlock so the two "here is a secret"
    // surfaces read the same.
    passkeyReveal: {
      padding: 12,
      borderRadius: radius,
      border: "1px solid #fde68a",
      background: "#fffbeb",
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
      fontSize: 13,
      wordBreak: "break-all",
      userSelect: "all",
      display: "flex",
      flexDirection: "column",
      gap: 8,
    },
    passkeyRevealActions: { display: "flex", gap: 8, alignItems: "center" },
  };
}

export function buildExportKeyStyles(
  appearance?: LoginPanelAppearance,
): Record<ExportKeyPanelSlot, CSSProperties> {
  const radius = appearance?.radius ?? DEFAULT_RADIUS;
  const accent = appearance?.accent ?? DEFAULT_ACCENT;

  const baseButton: CSSProperties = {
    flex: 1,
    padding: "10px 12px",
    borderRadius: radius,
    border: "1px solid #d4d4d8",
    background: "#ffffff",
    color: "#111111",
    fontSize: 14,
    cursor: "pointer",
  };

  return {
    root: {
      display: "flex",
      flexDirection: "column",
      gap: 12,
      maxWidth: 480,
      fontFamily:
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      color: "#111111",
    },
    title: { fontSize: 20, fontWeight: 600, margin: 0 },
    description: { fontSize: 13, color: "#52525b", lineHeight: 1.5, margin: 0 },
    input: {
      width: "100%",
      padding: "12px 14px",
      borderRadius: radius,
      border: "1px solid #d4d4d8",
      fontSize: 15,
      outline: "none",
      boxSizing: "border-box",
    },
    button: baseButton,
    primaryButton: { ...baseButton, background: accent, color: "#ffffff", borderColor: accent },
    secretBlock: {
      padding: 12,
      borderRadius: radius,
      border: "1px solid #fde68a",
      background: "#fffbeb",
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
      fontSize: 13,
      wordBreak: "break-all",
      userSelect: "all",
    },
    actions: { display: "flex", gap: 8 },
    error: { color: "#b91c1c", fontSize: 13 },
    muted: { color: "#71717a", fontSize: 13 },
  };
}
