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
  // for every button (no gradient, no primary/secondary split).
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
