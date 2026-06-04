// Default inline styles for the UI skeleton.
//
// We intentionally do not ship a CSS file: every style here can be replaced by
// passing `classNames={{ root: "...", button: "..." }}` to <LoginPanel>. The
// goal is "looks reasonable out of the box, fully overridable".
import type { CSSProperties } from "react";
import type { ExportKeyPanelSlot, LoginPanelAppearance, LoginPanelSlot } from "./types.js";

const DEFAULT_RADIUS = 8;
const DEFAULT_ACCENT = "#111111";

export function buildStyles(appearance?: LoginPanelAppearance): Record<LoginPanelSlot, CSSProperties> {
  const radius = appearance?.radius ?? DEFAULT_RADIUS;
  const accent = appearance?.accent ?? DEFAULT_ACCENT;

  const baseInput: CSSProperties = {
    width: "100%",
    padding: "10px 12px",
    borderRadius: radius,
    border: "1px solid #d4d4d8",
    fontSize: 14,
    outline: "none",
    boxSizing: "border-box",
  };

  const baseButton: CSSProperties = {
    width: "100%",
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
      gap: 16,
      maxWidth: 360,
      fontFamily:
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      color: "#111111",
    },
    title: { fontSize: 20, fontWeight: 600, margin: 0 },
    method: { display: "flex", flexDirection: "column", gap: 8 },
    methodLabel: { fontSize: 12, color: "#52525b", textTransform: "uppercase", letterSpacing: 0.4 },
    input: baseInput,
    button: baseButton,
    primaryButton: { ...baseButton, background: accent, color: "#ffffff", borderColor: accent },
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
