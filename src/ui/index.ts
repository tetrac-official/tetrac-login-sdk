// Optional UI entry — only loaded when the consumer imports it explicitly:
//   import { LoginPanel } from "@tetrac/login-sdk/ui";
//
// Keeping it on its own subpath preserves tree-shaking for apps that ship a
// fully custom login UI on top of `@tetrac/login-sdk/react`.
export { LoginPanel } from "./LoginPanel.js";
export { ExportKeyPanel } from "./ExportKeyPanel.js";
// Public CSPRNG helper — lets consumers generate a passkey with the exact SDK
// generator without rendering the panel. `encodeBase58` stays internal.
export { generateStrongPasskey } from "./passkey.js";
export type {
  LoginMethod,
  LoginPanelProps,
  LoginPanelSlot,
  LoginPanelAppearance,
  WalletConnector,
  HardwareWalletToggleConfig,
  PasskeyGeneratorConfig,
  PasskeyGeneratorShowFor,
  ExportKeyPanelProps,
  ExportKeyPanelSlot,
  ExportKeyPanelLabels,
} from "./types.js";
