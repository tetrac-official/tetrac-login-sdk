/**
 * @jest-environment jsdom
 *
 * H-3 — WHERE the passkey length floor is enforced.
 *
 * The floor itself is unit-tested in audit-h3-passkey-floor.test.ts. This file pins the two
 * boundaries that make it correct rather than merely present:
 *
 *   1. `registerWithEmail` enforces it, so an integrator who builds their own UI cannot
 *      bypass it by not using <EmailMethod>.
 *   2. `loginWithEmail` does NOT, so an account created before the floor keeps its wallets.
 *
 * Getting (2) wrong turns a hardening change into permanent data loss for existing users.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";

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
      registerWithBiometric: jest.fn(),
      loginWithBiometric: jest.fn(),
    }),
  }),
  { virtual: true },
);

jest.mock("../src/client/webauthn", () => ({
  isBiometricAvailable: async () => false,
}));

import { EmailMethod } from "../src/ui/EmailMethod";
import { AuthClient } from "../src/client/authClient";
import { MIN_PASSKEY_LENGTH } from "../src/core/crypto";

const emailStyles = {} as Record<string, React.CSSProperties>;
const noop = () => {};

const SHORT = "hunter2";
const LONG = "correct horse battery staple";

beforeEach(() => {
  mockRegisterWithEmail.mockClear();
  mockLoginWithEmail.mockClear();
});

function client() {
  return new AuthClient({
    apiBaseUrl: "/api/auth",
    config: { appId: "floor.example", origin: "https://floor.example" },
  });
}

describe("AuthClient — the floor covers custom UIs", () => {
  it("🚨 registerWithEmail rejects a short passkey before any network call", async () => {
    // jsdom has no global fetch; install one so "was it called?" is observable.
    const fetchMock = jest.fn();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;
    await expect(client().registerWithEmail({ email: "new@example.com", passkey: SHORT })).rejects.toThrow(
      new RegExp(`at least ${MIN_PASSKEY_LENGTH} characters`, "i"),
    );
    // It must fail BEFORE deriving and POSTing — otherwise a weak account is half-created.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("🚨 loginWithEmail does NOT reject a short passkey", async () => {
    // The existing-user path. It will fail later for other reasons (no server here), but it
    // must NOT fail with the length error — that would strand wallets created before the floor.
    await expect(client().loginWithEmail({ email: "old@example.com", passkey: SHORT })).rejects.not.toThrow(
      new RegExp(`at least ${MIN_PASSKEY_LENGTH} characters`, "i"),
    );
  });
});

describe("<EmailMethod /> — the floor is visible before submit", () => {
  function renderEmail(props: Record<string, unknown> = {}) {
    return render(
      <EmailMethod mode="auto" styles={emailStyles} onSuccess={noop} onError={noop} {...props} />,
    );
  }

  const typePasskey = (value: string) => {
    const field = document.querySelector('input[type="password"]') as HTMLInputElement;
    fireEvent.change(field, { target: { value } });
    return field;
  };
  const emailField = () => document.querySelector('input[type="email"]') as HTMLInputElement;
  const submitBtn = () => screen.getByRole("button", { name: /continue with email/i });

  it("🚨 blocks submit and explains why while the typed passkey is too short", () => {
    renderEmail({ passkeyGenerator: false }); // generator off = the typed path
    fireEvent.change(emailField(), { target: { value: "new@example.com" } });
    typePasskey(SHORT);

    expect((submitBtn() as HTMLButtonElement).disabled).toBe(true);
    expect(document.body.textContent).toMatch(new RegExp(`${MIN_PASSKEY_LENGTH} characters`));
  });

  it("unblocks once the passkey clears the floor", () => {
    renderEmail({ passkeyGenerator: false });
    fireEvent.change(emailField(), { target: { value: "new@example.com" } });
    typePasskey(LONG);

    expect((submitBtn() as HTMLButtonElement).disabled).toBe(false);
    expect(document.body.textContent).not.toMatch(new RegExp(`${MIN_PASSKEY_LENGTH} characters`));
  });

  it("🚨 SIGN-IN is never blocked by the floor", () => {
    // An existing account may hold a shorter passkey. Blocking here would lock the user out
    // of wallets nothing else can decrypt.
    renderEmail({ mode: "signin", passkeyGenerator: false });
    fireEvent.change(emailField(), { target: { value: "old@example.com" } });
    typePasskey(SHORT);

    expect((submitBtn() as HTMLButtonElement).disabled).toBe(false);
    expect(document.body.textContent).not.toMatch(new RegExp(`${MIN_PASSKEY_LENGTH} characters`));
  });

  it("the auto-generated default never trips the floor", () => {
    renderEmail(); // generator on by default — fills + reveals on mount
    fireEvent.change(emailField(), { target: { value: "new@example.com" } });

    const field = document.querySelector('input[type="password"]') as HTMLInputElement;
    expect(field.value.length).toBeGreaterThanOrEqual(MIN_PASSKEY_LENGTH);
    expect((submitBtn() as HTMLButtonElement).disabled).toBe(false);
  });
});
