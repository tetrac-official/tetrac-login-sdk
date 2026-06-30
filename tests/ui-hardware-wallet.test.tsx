/**
 * @jest-environment jsdom
 *
 * UI hardware-wallet plumbing (docs/LEDGER_UI_SUPPORT_PRD.md). Proves the
 * `hardwareWallet` flag flows connector → connectWallet on the login path and
 * panel → reveal on the reveal path, that the connector's own signal wins over
 * the LoginPanel-level fallback, and that the software path still defaults to
 * `false`/`undefined` (the regression guard for §1.3).
 *
 * The UI components import the `@tetrac/login-sdk/react` subpath (resolved to
 * `dist` only after a build), so we mock it virtually and assert the args the
 * panels forward — exactly the unit shape the PRD §8 calls for.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const mockConnectWallet = jest.fn(async () => ({}) as never);
const mockReveal = jest.fn(async () => undefined);
let mockUser: { authMethod: string } | null = { authMethod: "wallet" };

jest.mock(
  "@tetrac/login-sdk/react",
  () => ({
    useAuth: () => ({ connectWallet: mockConnectWallet }),
    useExportKey: () => ({
      reveal: mockReveal,
      clear: jest.fn(),
      plaintext: null,
      loading: false,
      error: null,
    }),
    useUser: () => ({ user: mockUser }),
  }),
  { virtual: true },
);

import { WalletMethod } from "../src/ui/WalletMethod";
import { ExportKeyPanel } from "../src/ui/ExportKeyPanel";
import { LoginPanel } from "../src/ui/LoginPanel";
import type { WalletConnector } from "../src/ui/types";
import type { EncryptedWallet } from "../src/core/types";

const signMessage = async (m: Uint8Array) => m;
const noStyles = {} as Record<string, React.CSSProperties>;
const noop = () => {};

beforeEach(() => {
  mockConnectWallet.mockClear();
  mockReveal.mockClear();
  mockUser = { authMethod: "wallet" };
});

describe("WalletMethod — login path threads hardwareWallet", () => {
  it("forwards hardwareWallet:true when the connector reports it", async () => {
    const connector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage, hardwareWallet: true }),
    };
    render(<WalletMethod connector={connector} styles={noStyles} onSuccess={noop} onError={noop} />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith({ publicKey: "pk", signMessage, hardwareWallet: true });
  });

  it("defaults hardwareWallet:false when the connector omits it (software-path guard)", async () => {
    const connector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage }),
    };
    render(<WalletMethod connector={connector} styles={noStyles} onSuccess={noop} onError={noop} />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith({ publicKey: "pk", signMessage, hardwareWallet: false });
  });

  it("falls back to the panel-level hint when the connector omits the flag", async () => {
    const connector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage }),
    };
    render(
      <WalletMethod connector={connector} hardwareWallet styles={noStyles} onSuccess={noop} onError={noop} />,
    );
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith(expect.objectContaining({ hardwareWallet: true }));
  });

  it("lets the connector's explicit value win over the panel-level hint", async () => {
    const connector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage, hardwareWallet: false }),
    };
    render(
      <WalletMethod connector={connector} hardwareWallet styles={noStyles} onSuccess={noop} onError={noop} />,
    );
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith(expect.objectContaining({ hardwareWallet: false }));
  });
});

describe("LoginPanel — forwards hardwareWallet to the wallet method", () => {
  it("threads its hardwareWallet prop down to connectWallet", async () => {
    const connector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage }),
    };
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWallet />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith(expect.objectContaining({ hardwareWallet: true }));
  });
});

describe("ExportKeyPanel — reveal path threads hardwareWallet", () => {
  const wallet = {} as EncryptedWallet; // truthy; useExportKey is mocked

  it("forwards hardwareWallet:true into reveal", async () => {
    render(<ExportKeyPanel wallet={wallet} walletSignMessage={signMessage} hardwareWallet />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockReveal).toHaveBeenCalled());
    expect(mockReveal).toHaveBeenCalledWith({ signMessage, hardwareWallet: true });
  });

  it("leaves hardwareWallet undefined when omitted (software-path guard)", async () => {
    render(<ExportKeyPanel wallet={wallet} walletSignMessage={signMessage} />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(mockReveal).toHaveBeenCalled());
    expect(mockReveal).toHaveBeenCalledWith({ signMessage, hardwareWallet: undefined });
  });
});
