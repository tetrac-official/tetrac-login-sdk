// Optional UI entry — only loaded when the consumer imports it explicitly:
//   import { LoginPanel } from "@tetrac/login-sdk/ui";
//
// Keeping it on its own subpath preserves tree-shaking for apps that ship a
// fully custom login UI on top of `@tetrac/login-sdk/react`.
export { LoginPanel } from "./LoginPanel.js";
export type {
  LoginMethod,
  LoginPanelProps,
  LoginPanelSlot,
  LoginPanelAppearance,
  WalletConnector,
} from "./types.js";
