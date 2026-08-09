/**
 * @jest-environment jsdom
 *
 * LoginPanel UX (0.5.0): the hardware-wallet toggle + the passkey generator.
 * Proves (a) the base58 encoder / CSPRNG generator are correct (leading zeros,
 * unambiguous alphabet, entropy clamp, uniqueness); (b) the toggle only renders
 * when opted in AND the wallet method actually rendered, drives the hardwareWallet
 * flag (connector still wins), honours controlled/uncontrolled semantics, and is
 * an accessible switch; (c) the passkey generator fills + auto-reveals a CSPRNG
 * value, gates on emailMode, never persists, and its clipboard copy is best-effort
 * with no auto-wipe. Regression: a default panel renders unchanged.
 *
 * jest-dom is NOT installed in this repo (the sibling ui-hardware-wallet suite
 * uses no jest-dom matchers), so this file uses only plain DOM property/attribute
 * assertions. `tests/jest.setup.ts` backs `crypto` with Node's webcrypto, so
 * `crypto.getRandomValues` works for the real-CSPRNG assertions.
 *
 * The UI components import the `@tetrac/login-sdk/react` subpath (resolved to
 * `dist` only after a build), so we mock it virtually — exactly as the sibling
 * ui-hardware-wallet suite does.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";

const mockConnectWallet = jest.fn(async () => ({}) as never);
const mockRegisterWithEmail = jest.fn(async () => ({}) as never);
const mockLoginWithEmail = jest.fn(async () => ({}) as never);

jest.mock(
  "@tetrac/login-sdk/react",
  () => ({
    useAuth: () => ({
      connectWallet: mockConnectWallet,
      registerWithEmail: mockRegisterWithEmail,
      loginWithEmail: mockLoginWithEmail,
      // Present so BiometricMethod's useAuth() destructure never crashes if a full
      // default panel is rendered.
      registerWithBiometric: jest.fn(),
      loginWithBiometric: jest.fn(),
    }),
  }),
  { virtual: true },
);

// BiometricMethod pulls in isBiometricAvailable from the client webauthn module;
// stub it so a default-methods render resolves to "unavailable" and never touches
// real WebAuthn in jsdom.
jest.mock("../src/client/webauthn", () => ({
  isBiometricAvailable: async () => false,
}));

import { LoginPanel } from "../src/ui/LoginPanel";
import { EmailMethod } from "../src/ui/EmailMethod";
import { encodeBase58, generateStrongPasskey } from "../src/ui/passkey";
import type { WalletConnector } from "../src/ui/types";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const UNAMBIGUOUS = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
const signMessage = async (m: Uint8Array) => m;
const noop = () => {};
const emailStyles = {} as Record<string, React.CSSProperties>;

beforeEach(() => {
  mockConnectWallet.mockClear();
  mockRegisterWithEmail.mockClear();
  mockLoginWithEmail.mockClear();
});

// ---------------------------------------------------------------------------
// base58 encoder — pure crypto correctness
// ---------------------------------------------------------------------------
describe("encodeBase58 — correctness", () => {
  it("encodes empty input to the empty string", () => {
    expect(encodeBase58(new Uint8Array([]))).toBe("");
  });

  it("maps each leading zero byte to exactly one '1'", () => {
    expect(encodeBase58(new Uint8Array([0]))).toBe("1");
    expect(encodeBase58(new Uint8Array([0, 0, 0]))).toBe("111");
    expect(encodeBase58(new Uint8Array(4))).toBe("1111");
    // Leading zeros preserved AND the tail encoded: [0,0,1] → "11" + encode(1)="2".
    expect(encodeBase58(new Uint8Array([0, 0, 1]))).toBe("112");
  });

  it("matches canonical Bitcoin base58 vectors", () => {
    expect(encodeBase58(new Uint8Array([0x61]))).toBe("2g"); // 'a'
    expect(encodeBase58(new Uint8Array([0x62, 0x62, 0x62]))).toBe("a3gV"); // 'bbb'
    expect(encodeBase58(new Uint8Array([0x63, 0x63, 0x63]))).toBe("aPEr"); // 'ccc'
  });

  it("emits only unambiguous glyphs (never 0 O I l)", () => {
    const s = encodeBase58(new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff)));
    expect(s).toMatch(UNAMBIGUOUS);
    expect(s).not.toMatch(/[0OIl]/);
    for (const ch of s) expect(ALPHABET.indexOf(ch)).toBeGreaterThanOrEqual(0);
  });

  it("is a faithful (unbiased) representation — round-trips through BigInt", () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0xff]);
    const enc = encodeBase58(bytes);
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let dec = 0n;
    for (const ch of enc) dec = dec * 58n + BigInt(ALPHABET.indexOf(ch));
    expect(dec).toBe(n);
  });
});

// ---------------------------------------------------------------------------
// generateStrongPasskey — CSPRNG, clamp, uniqueness
// ---------------------------------------------------------------------------
describe("generateStrongPasskey", () => {
  it("defaults to a ~32-char unambiguous string", () => {
    const pk = generateStrongPasskey();
    expect(pk).toMatch(UNAMBIGUOUS);
    expect(pk.length).toBeGreaterThanOrEqual(28);
    expect(pk.length).toBeLessThanOrEqual(34);
  });

  it("clamps entropy to a 16-byte (128-bit) minimum", () => {
    // 8 requested → raised to 16 bytes → ~21 base58 chars; assert a generous floor.
    expect(generateStrongPasskey(8).length).toBeGreaterThanOrEqual(18);
    expect(generateStrongPasskey(1).length).toBeGreaterThanOrEqual(18);
  });

  it("tolerates fractional / NaN / negative byte counts without throwing", () => {
    expect(() => generateStrongPasskey(12.9)).not.toThrow();
    expect(() => generateStrongPasskey(NaN)).not.toThrow();
    expect(() => generateStrongPasskey(-4)).not.toThrow();
    expect(generateStrongPasskey(-4).length).toBeGreaterThanOrEqual(18);
    expect(generateStrongPasskey(NaN).length).toBeGreaterThanOrEqual(28); // default 24
  });

  it("produces unique values across many draws (real CSPRNG, not Math.random)", () => {
    const set = new Set<string>();
    for (let i = 0; i < 500; i++) set.add(generateStrongPasskey());
    expect(set.size).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// Hardware-wallet toggle
// ---------------------------------------------------------------------------
const connector: WalletConnector = { connect: async () => ({ publicKey: "pk", signMessage }) };

describe("hardwareWalletToggle — placement + gating", () => {
  it("renders the switch directly UNDER the wallet button", () => {
    render(
      <LoginPanel
        methods={["email", "biometric", "wallet"]}
        walletConnector={connector}
        hardwareWalletToggle
      />,
    );
    const sw = screen.getByRole("switch");
    const label = sw.closest("label")!;
    const walletBtn = screen.getByRole("button", { name: /wallet/i });
    // The toggle's <label> follows the wallet button in DOM order.
    expect(walletBtn.compareDocumentPosition(label) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("renders NO toggle when hardwareWalletToggle is omitted", () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} />);
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it("renders NO toggle when 'wallet' is not in methods", () => {
    render(<LoginPanel methods={["email"]} walletConnector={connector} hardwareWalletToggle />);
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it("renders NO toggle when there is no walletConnector (stub branch)", () => {
    render(<LoginPanel methods={["wallet"]} hardwareWalletToggle />);
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.getByText(/walletConnector/i)).toBeTruthy();
  });
});

describe("hardwareWalletToggle — flag production (connector precedence preserved)", () => {
  it("flipping the switch drives connectWallet with hardwareWallet:true", async () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWalletToggle />);
    fireEvent.click(screen.getByRole("switch"));
    fireEvent.click(screen.getByRole("button", { name: /wallet/i }));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    expect(mockConnectWallet).toHaveBeenCalledWith(expect.objectContaining({ hardwareWallet: true }));
  });

  it("connector-reported value still wins over the toggle", async () => {
    const hwConnector: WalletConnector = {
      connect: async () => ({ publicKey: "pk", signMessage, hardwareWallet: false }),
    };
    render(<LoginPanel methods={["wallet"]} walletConnector={hwConnector} hardwareWalletToggle />);
    fireEvent.click(screen.getByRole("switch")); // toggle ON …
    fireEvent.click(screen.getByRole("button", { name: /wallet/i }));
    await waitFor(() => expect(mockConnectWallet).toHaveBeenCalled());
    // … but the connector's explicit false wins.
    expect(mockConnectWallet).toHaveBeenCalledWith(expect.objectContaining({ hardwareWallet: false }));
  });
});

describe("hardwareWalletToggle — controlled vs uncontrolled", () => {
  it("uncontrolled: seeds ON from defaultOn", () => {
    render(
      <LoginPanel
        methods={["wallet"]}
        walletConnector={connector}
        hardwareWalletToggle={{ defaultOn: true }}
      />,
    );
    expect((screen.getByRole("switch") as HTMLInputElement).checked).toBe(true);
  });

  it("uncontrolled: seeds from hardwareWallet when the config has no defaultOn", () => {
    render(
      <LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWallet hardwareWalletToggle />,
    );
    expect((screen.getByRole("switch") as HTMLInputElement).checked).toBe(true);
  });

  it("controlled: fires onHardwareWalletChange and only reflects the prop", () => {
    const onChange = jest.fn();
    const { rerender } = render(
      <LoginPanel
        methods={["wallet"]}
        walletConnector={connector}
        hardwareWalletToggle
        hardwareWallet={false}
        onHardwareWalletChange={onChange}
      />,
    );
    const sw = () => screen.getByRole("switch") as HTMLInputElement;
    expect(sw().checked).toBe(false);
    fireEvent.click(sw());
    expect(onChange).toHaveBeenCalledWith(true);
    // Controlled → internal state did NOT change; the prop is source of truth.
    expect(sw().checked).toBe(false);
    // Parent updates the prop → now reflected.
    rerender(
      <LoginPanel
        methods={["wallet"]}
        walletConnector={connector}
        hardwareWalletToggle
        hardwareWallet={true}
        onHardwareWalletChange={onChange}
      />,
    );
    expect(sw().checked).toBe(true);
  });
});

describe("hardwareWalletToggle — a11y", () => {
  it("is a focusable native checkbox with role=switch, aria-checked, and a label", () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWalletToggle />);
    const sw = screen.getByRole("switch") as HTMLInputElement;
    expect(sw.tagName).toBe("INPUT");
    expect(sw.type).toBe("checkbox");
    expect(sw.getAttribute("aria-checked")).toBe("false");
    // Reachable / focusable (not display:none). Wrapped in act because the
    // toggle's onFocus updates state (the focus ring).
    act(() => sw.focus());
    expect(document.activeElement).toBe(sw);
    // Space toggles a checkbox natively; fireEvent.click routes label→checkbox.
    fireEvent.click(sw);
    expect(sw.getAttribute("aria-checked")).toBe("true");
  });

  it("toggles on Enter — role=switch contract (§7 keyboard scenario)", () => {
    // A native checkbox activates on Space (delegated to the browser; jsdom does
    // not synthesize the Space→click, so we assert the click path above for Space
    // and the explicit Enter handler here). role="switch" adds Enter, which the
    // component wires via onKeyDown.
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWalletToggle />);
    const sw = screen.getByRole("switch") as HTMLInputElement;
    expect(sw.getAttribute("aria-checked")).toBe("false");
    act(() => sw.focus());
    expect(document.activeElement).toBe(sw); // reachable by keyboard focus
    fireEvent.keyDown(sw, { key: "Enter", code: "Enter" });
    expect(sw.getAttribute("aria-checked")).toBe("true");
    // Enter again toggles back off — symmetric.
    fireEvent.keyDown(sw, { key: "Enter", code: "Enter" });
    expect(sw.getAttribute("aria-checked")).toBe("false");
    // Space is handled natively by the browser; jsdom does not simulate the
    // Space→toggle, so a bare keyDown must NOT double-fire our Enter handler.
    fireEvent.keyDown(sw, { key: " ", code: "Space" });
    expect(sw.getAttribute("aria-checked")).toBe("false");
  });

  it("associates the label — getByLabelText resolves the switch input", () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWalletToggle />);
    const byLabel = screen.getByLabelText(/Ledger hardware wallet/i);
    expect(byLabel).toBe(screen.getByRole("switch"));
  });

  it("wires the description via aria-describedby so screen readers announce the caveat", () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} hardwareWalletToggle />);
    const sw = screen.getByRole("switch") as HTMLInputElement;
    const descId = sw.getAttribute("aria-describedby");
    expect(descId).toBeTruthy();
    const descEl = document.getElementById(descId!);
    expect(descEl).toBeTruthy();
    expect(descEl!.textContent).toMatch(/same Ledger to unlock\/reveal later/i);
  });

  it("omits aria-describedby when the description is disabled (description: null)", () => {
    render(
      <LoginPanel
        methods={["wallet"]}
        walletConnector={connector}
        hardwareWalletToggle={{ description: null }}
      />,
    );
    const sw = screen.getByRole("switch") as HTMLInputElement;
    expect(sw.getAttribute("aria-describedby")).toBeNull();
  });

  it("a ReactNode label with ariaLabel exposes that accessible name (no generic fallback)", () => {
    render(
      <LoginPanel
        methods={["wallet"]}
        walletConnector={connector}
        hardwareWalletToggle={{
          label: <span>Ledger user</span>,
          ariaLabel: "I am using a Ledger hardware wallet",
        }}
      />,
    );
    const byLabel = screen.getByLabelText(/I am using a Ledger hardware wallet/i);
    expect(byLabel).toBe(screen.getByRole("switch"));
  });

  it("regression: no toggle prop → no switch rendered", () => {
    render(<LoginPanel methods={["wallet"]} walletConnector={connector} />);
    expect(screen.queryByRole("switch")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Passkey generator (via EmailMethod, which owns the field)
// ---------------------------------------------------------------------------
describe("passkeyGenerator — fill + enable + reveal", () => {
  it("clicking generate fills the passkey, reveals it, enables submit, calls onGenerate", () => {
    const onGenerate = jest.fn();
    render(
      <EmailMethod
        mode="signup"
        styles={emailStyles}
        passkeyGenerator={{ onGenerate }}
        onSuccess={noop}
        onError={noop}
      />,
    );
    // The field is ALREADY filled on mount — a generated passkey is the default path now,
    // not something the user has to discover a button for.
    const onMount = document.querySelector('input[type="password"]') as HTMLInputElement;
    const firstValue = onMount.value; // capture the STRING — the element is live
    expect(firstValue).toMatch(UNAMBIGUOUS);
    expect(onGenerate).toHaveBeenCalledTimes(1);

    // The button REGENERATES.
    fireEvent.click(screen.getByRole("button", { name: /generate a strong passkey/i }));

    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(pwInput.value).toMatch(UNAMBIGUOUS);
    expect(pwInput.value).not.toBe(firstValue); // re-generate produced a NEW value
    expect(pwInput.value.length).toBeGreaterThanOrEqual(18);
    expect(onGenerate).toHaveBeenCalledTimes(2);
    expect(onGenerate).toHaveBeenCalledWith(pwInput.value);

    // Reveal appears with the same value + a "can't be recovered" warning.
    expect(screen.getByText(pwInput.value)).toBeTruthy();
    expect(screen.getByText(/can't be recovered/i)).toBeTruthy();

    // Submit enables once email is also present.
    fireEvent.change(screen.getByPlaceholderText("you@example.com"), { target: { value: "a@b.co" } });
    const submit = screen.getByRole("button", { name: /continue with email/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
  });

  it("the passkey input carries paddingRight only when the generator is active", () => {
    const { rerender } = render(
      <EmailMethod mode="signup" styles={emailStyles} passkeyGenerator onSuccess={noop} onError={noop} />,
    );
    let pw = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(pw.style.paddingRight).toBe("48px");

    // Explicit opt-OUT is what removes it now — omitting the prop leaves it ON.
    rerender(
      <EmailMethod
        mode="signup"
        styles={emailStyles}
        passkeyGenerator={false}
        onSuccess={noop}
        onError={noop}
      />,
    );
    pw = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(pw.style.paddingRight).toBe("");
  });
});

describe("passkeyGenerator — reveal lifecycle + no persistence", () => {
  it("dismiss clears the reveal but keeps the field filled; nothing is persisted", () => {
    const setItem = jest.spyOn(Storage.prototype, "setItem");
    render(
      <EmailMethod mode="signup" styles={emailStyles} passkeyGenerator onSuccess={noop} onError={noop} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /generate a strong passkey/i }));
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement;
    const value = pwInput.value;
    expect(screen.getByText(/can't be recovered/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^dismiss$/i }));
    expect(screen.queryByText(/can't be recovered/i)).toBeNull();
    // Field value persists — only the reveal was dismissed.
    expect((document.querySelector('input[type="password"]') as HTMLInputElement).value).toBe(value);

    expect(setItem).not.toHaveBeenCalled();
    setItem.mockRestore();
  });

  it("unmount clears the reveal state without throwing", () => {
    const { unmount } = render(
      <EmailMethod mode="signup" styles={emailStyles} passkeyGenerator onSuccess={noop} onError={noop} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /generate a strong passkey/i }));
    expect(() => unmount()).not.toThrow();
  });
});

describe("passkeyGenerator — clipboard copy (best-effort, no auto-wipe)", () => {
  it("copies the value, flashes 'Copied', and never schedules a clipboard wipe", async () => {
    jest.useFakeTimers();
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    try {
      render(
        <EmailMethod mode="signup" styles={emailStyles} passkeyGenerator onSuccess={noop} onError={noop} />,
      );
      fireEvent.click(screen.getByRole("button", { name: /generate a strong passkey/i }));
      const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement;
      const value = pwInput.value;

      fireEvent.click(screen.getByRole("button", { name: /^copy$/i }));
      // Flush the awaited writeText microtask + the setCopiedFlash state update.
      await act(async () => {
        await Promise.resolve();
      });
      expect(writeText).toHaveBeenCalledTimes(1);
      expect(writeText).toHaveBeenCalledWith(value);

      // Advance well past any reasonable wipe window: NO second writeText("") fires
      // (DECIDED-4: the generated passkey must NOT be auto-wiped from the clipboard).
      act(() => {
        jest.advanceTimersByTime(60_000);
      });
      expect(writeText).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });

  it("swallows a rejecting clipboard and keeps the reveal visible", async () => {
    const writeText = jest.fn().mockRejectedValue(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    render(
      <EmailMethod mode="signup" styles={emailStyles} passkeyGenerator onSuccess={noop} onError={noop} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /generate a strong passkey/i }));
    fireEvent.click(screen.getByRole("button", { name: /^copy$/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    // Value stays available to copy manually.
    expect(screen.getByText(/can't be recovered/i)).toBeTruthy();
  });
});

describe("passkeyGenerator — gating on emailMode", () => {
  const gen = (mode: "signin" | "signup" | "auto", pg: EmailMethodPasskeyProp) =>
    render(
      <EmailMethod mode={mode} styles={emailStyles} passkeyGenerator={pg} onSuccess={noop} onError={noop} />,
    );

  it("hidden for signin by default", () => {
    gen("signin", true);
    expect(screen.queryByRole("button", { name: /generate a strong passkey/i })).toBeNull();
  });
  it("shown for signup and auto by default", () => {
    const { unmount } = gen("signup", true);
    expect(screen.getByRole("button", { name: /generate a strong passkey/i })).toBeTruthy();
    unmount();
    gen("auto", true);
    expect(screen.getByRole("button", { name: /generate a strong passkey/i })).toBeTruthy();
  });
  it("showFor:'always' overrides signin", () => {
    gen("signin", { showFor: "always" });
    expect(screen.getByRole("button", { name: /generate a strong passkey/i })).toBeTruthy();
  });
  it("showFor:'signup' hides on auto", () => {
    gen("auto", { showFor: "signup" });
    expect(screen.queryByRole("button", { name: /generate a strong passkey/i })).toBeNull();
  });
});

// Type alias mirroring the prop so the gating helper stays typed without `any`.
type EmailMethodPasskeyProp = React.ComponentProps<typeof EmailMethod>["passkeyGenerator"];

// ---------------------------------------------------------------------------
// Regression — a default panel / EmailMethod is byte-identical to today
// ---------------------------------------------------------------------------
describe("regression — default render is unchanged", () => {
  it("EmailMethod with the generator OPTED OUT: plain current-password input, no wrapper, no button", () => {
    render(
      <EmailMethod
        mode="auto"
        styles={emailStyles}
        passkeyGenerator={false}
        onSuccess={noop}
        onError={noop}
      />,
    );
    expect(screen.queryByRole("button", { name: /generate a strong passkey/i })).toBeNull();
    const pw = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(pw.getAttribute("autocomplete")).toBe("current-password");
    expect(pw.style.paddingRight).toBe("");
    // No positioned passkeyField wrapper around the input.
    expect((pw.parentElement as HTMLElement).tagName).toBe("FORM");
  });

  it("LoginPanel with no new props renders no switch, and DOES offer the generator", () => {
    render(<LoginPanel methods={["email", "wallet"]} walletConnector={connector} emailMode="signup" />);
    expect(screen.queryByRole("switch")).toBeNull();
    // Generated-by-default: the out-of-the-box panel no longer ships a bare text field for
    // the secret that encrypts the wallet.
    expect(screen.queryByRole("button", { name: /generate a strong passkey/i })).not.toBeNull();
  });
});
