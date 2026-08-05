/**
 * @jest-environment jsdom
 *
 * BiometricMethod must handle PrfUnavailableError as a DEVICE CAPABILITY VERDICT,
 * not as an ordinary error string.
 *
 * Why this needs a test: `isBiometricAvailable()` is a UVPAA probe — it answers
 * "does a platform authenticator exist?", NOT "does it support the PRF extension?".
 * A device can have Touch ID and still lack PRF, and PRF support is only reported in
 * the credential's extension results. So the panel renders an enabled button, the
 * user taps it, and the SDK throws. Before this fix the raw developer-facing message
 * ("[tetrac] This authenticator does not support the WebAuthn PRF extension, so it
 * cannot derive an encryption key without storing one on the device…") was rendered
 * straight into the UI, and the button stayed live so the user could retry into the
 * exact same permanent failure.
 *
 * Mocks `@tetrac/login-sdk/react` virtually (the subpath only resolves against dist/
 * after a build), matching the sibling ui-* suites.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { PrfUnavailableError } from "../src/client/webauthn";

const mockRegisterWithBiometric = jest.fn();
const mockLoginWithBiometric = jest.fn();

jest.mock(
  "@tetrac/login-sdk/react",
  () => ({
    useAuth: () => ({
      registerWithBiometric: mockRegisterWithBiometric,
      loginWithBiometric: mockLoginWithBiometric,
    }),
  }),
  { virtual: true },
);

// A platform authenticator EXISTS (UVPAA true) — the PRF gap is invisible here.
jest.mock("../src/client/webauthn", () => {
  const actual = jest.requireActual("../src/client/webauthn");
  return { ...actual, isBiometricAvailable: jest.fn(async () => true) };
});

import { BiometricMethod } from "../src/ui/BiometricMethod";

const styles = {} as Record<string, React.CSSProperties>;

function renderPanel(onError = jest.fn()) {
  const onSuccess = jest.fn();
  render(
    <BiometricMethod
      registration={null}
      userName="user@example.com"
      styles={styles}
      onSuccess={onSuccess}
      onError={onError}
    />,
  );
  return { onSuccess, onError };
}

describe("BiometricMethod — non-PRF authenticator", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("retires the option and shows a user-facing message instead of the raw error", async () => {
    mockRegisterWithBiometric.mockRejectedValue(new PrfUnavailableError());
    const { onSuccess, onError } = renderPanel();

    const button = await screen.findByRole("button");
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.queryByRole("button")).toBeNull(); // no retry into a permanent failure
    });

    const text = document.body.textContent ?? "";
    expect(text).toContain("Continue with email or a wallet instead.");
    // The developer-facing message never reaches the user.
    expect(text).not.toContain("[tetrac]");
    expect(text).not.toContain("PRF extension");

    // The host app is still told, so it can steer the user itself.
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0][0]).toBeInstanceOf(PrfUnavailableError);
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("still surfaces ORDINARY errors inline and keeps the button live", async () => {
    // A cancelled ceremony is recoverable — the user should be able to try again.
    mockRegisterWithBiometric.mockRejectedValue(new Error("Passkey registration was cancelled"));
    renderPanel();

    fireEvent.click(await screen.findByRole("button"));

    await waitFor(() => {
      expect(document.body.textContent).toContain("Passkey registration was cancelled");
    });
    expect(screen.queryByRole("button")).not.toBeNull();
  });
});
