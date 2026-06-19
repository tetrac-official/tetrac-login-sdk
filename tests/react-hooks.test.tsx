/**
 * @jest-environment jsdom
 *
 * React-layer hardening tests (src/react/*, previously 0% covered). Runs in jsdom so
 * the hooks can mount; Node's WebCrypto backs `crypto.subtle` (jsdom omits it). Focus:
 * the security-relevant behaviors — vault-lock reactivity (useSigner), re-auth-to-reveal
 * (useExportKey), status transitions (useAuth) — plus the audit's React-layer finding
 * F9 (the biometric registration descriptor surviving logout).
 */
import React from "react";
import { webcrypto } from "node:crypto";
import { renderHook, act } from "@testing-library/react";
import { AuthProvider } from "../src/react/AuthProvider";
import { useSigner } from "../src/react/useSigner";
import { useAuth } from "../src/react/useAuth";
import { useExportKey } from "../src/react/useExportKey";
import { useBiometricUnlock } from "../src/react/useBiometricUnlock";
import { armAppKey, lockVault, getAppKey, setSession, clearSession } from "../src/client/session";
import { encryptSecret, deriveAppKeyFromPasskey } from "../src/core/crypto";
import type { EncryptedWallet } from "../src/core/types";

// jsdom has no WebCrypto subtle — back the global with Node's implementation.
if (!(globalThis.crypto && "subtle" in globalThis.crypto)) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

const APP_ID = "test-app";
const EMAIL = "user@example.com";
const PASSKEY = "correct horse battery staple";
const ITER = 100_000;
const SECRET_HEX = "11".repeat(64); // 64-byte Solana-style secret, hex

// A minimal fetch stub: AuthProvider fetches /user-data on mount; reveal/sign are
// client-side and never hit the network. jsdom has no `Response` global, so we return
// a plain Response-shaped object (the client only reads .status/.ok/.json()).
function fakeRes(body: unknown, status = 200) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}
function stubFetch(user: unknown = null) {
  (global as unknown as { fetch: typeof fetch }).fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/user-data")) return fakeRes({ user });
    if (url.includes("/logout")) return fakeRes({ ok: true });
    return fakeRes({});
  }) as unknown as typeof fetch;
}

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider
      apiBaseUrl="/api/auth"
      config={{ appId: APP_ID, securityLevel: 1, autoLockMs: 60_000, lockOnHide: false }}
    >
      {children}
    </AuthProvider>
  );
}

beforeEach(() => {
  localStorage.clear();
  lockVault();
  stubFetch();
});
afterEach(() => lockVault());

describe("useSigner — vault-lock reactivity", () => {
  let wallet: EncryptedWallet;
  const appKey = "ab".repeat(32);
  beforeAll(async () => {
    wallet = {
      chain: "solana",
      role: "funds",
      publicKey: "x",
      encryptedSecret: await encryptSecret(SECRET_HEX, appKey),
    };
  });

  it("reports locked and refuses to sign when the vault is locked", async () => {
    lockVault();
    const { result } = renderHook(() => useSigner());
    expect(result.current.unlocked).toBe(false);
    // sign() guards on getAppKey() and throws synchronously when locked (before any decrypt).
    expect(() => result.current.sign(wallet, (s) => s)).toThrow(/vault is locked/i);
  });

  it("flips to unlocked on arm and decrypts; flips back on lock (useSyncExternalStore)", async () => {
    const { result } = renderHook(() => useSigner());

    act(() => armAppKey(appKey));
    expect(result.current.unlocked).toBe(true);
    await expect(result.current.sign(wallet, (s) => s)).resolves.toBe(SECRET_HEX);

    act(() => lockVault());
    expect(result.current.unlocked).toBe(false);
  });
});

describe("useAuth — status reflects the session + vault", () => {
  it("transitions unauthenticated → authenticated → session_expired → unauthenticated", async () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    await act(async () => {}); // flush mount effects
    expect(result.current.status).toBe("unauthenticated");

    await act(async () => {
      setSession({ publicKey: "pub1", authToken: "tok1", appKey: "ab".repeat(32), email: EMAIL });
    });
    expect(result.current.status).toBe("authenticated");
    expect(result.current.isAuthenticated).toBe(true);

    act(() => lockVault());
    expect(result.current.status).toBe("session_expired");
    expect(result.current.isLocked).toBe(true);

    await act(async () => {
      clearSession();
    });
    expect(result.current.status).toBe("unauthenticated");
  });
});

describe("useExportKey — re-auth to reveal", () => {
  it("reveals via a fresh ceremony, does NOT arm the vault, and clears", async () => {
    const appKey = deriveAppKeyFromPasskey(PASSKEY, EMAIL, ITER, APP_ID);
    const wallet: EncryptedWallet = {
      chain: "solana",
      role: "funds",
      publicKey: "x",
      encryptedSecret: await encryptSecret(SECRET_HEX, appKey),
    };
    // Persist the email + iteration count the { passkey } re-auth path reads, then lock.
    setSession({ publicKey: "pub1", authToken: "tok1", appKey, email: EMAIL, pbkdf2Iterations: ITER });
    lockVault();
    expect(getAppKey()).toBeNull();

    const { result } = renderHook(() => useExportKey(wallet), { wrapper });
    await act(async () => {});

    await act(async () => {
      await result.current.reveal({ passkey: PASSKEY });
    });
    expect(result.current.plaintext).toBe(SECRET_HEX);
    expect(getAppKey()).toBeNull(); // reveal derived a one-time key — vault stays locked

    act(() => result.current.clear());
    expect(result.current.plaintext).toBeNull();
  });

  it("surfaces an error and stays locked on a wrong passkey", async () => {
    const appKey = deriveAppKeyFromPasskey(PASSKEY, EMAIL, ITER, APP_ID);
    const wallet: EncryptedWallet = {
      chain: "solana",
      role: "funds",
      publicKey: "x",
      encryptedSecret: await encryptSecret(SECRET_HEX, appKey),
    };
    setSession({ publicKey: "pub1", authToken: "tok1", appKey, email: EMAIL, pbkdf2Iterations: ITER });
    lockVault();

    const { result } = renderHook(() => useExportKey(wallet), { wrapper });
    await act(async () => {});
    await act(async () => {
      await expect(result.current.reveal({ passkey: "wrong" })).rejects.toThrow(/re-authentication failed/i);
    });
    expect(result.current.plaintext).toBeNull();
  });
});

// F9 (audit zai-glm-52) — FIXED: importing useBiometricUnlock registers a clearSession
// hook that purges localStorage["ttc_biometric_reg"] on logout, alongside the client
// layer's marker + IndexedDB-blob purge. So logout leaves no stale descriptor behind.
describe("useBiometricUnlock — F9: descriptor purged on logout", () => {
  const REG_KEY = "ttc_biometric_reg";
  const MARKER_KEY = "ttc_biometric_unlock";
  const REG = JSON.stringify({ credentialId: "cred123", salt: "s", rpId: "localhost", mode: "prf" });

  it("logout purges BOTH the client marker and the React descriptor", () => {
    localStorage.setItem(MARKER_KEY, "cred123"); // client-layer marker (hasBiometricUnlock)
    localStorage.setItem(REG_KEY, REG); // React-layer descriptor

    clearSession(); // logout — fires both clearSession hooks

    expect(localStorage.getItem(MARKER_KEY)).toBeNull(); // client hook purged it
    expect(localStorage.getItem(REG_KEY)).toBeNull(); // F9 fixed: descriptor purged too
  });

  it("after logout the hook reports disabled with no lingering descriptor", async () => {
    localStorage.setItem(MARKER_KEY, "cred123");
    localStorage.setItem(REG_KEY, REG);
    clearSession();

    const { result } = renderHook(() => useBiometricUnlock(), { wrapper });
    await act(async () => {});
    expect(result.current.isEnabled).toBe(false); // marker gone → disabled…
    expect(localStorage.getItem(REG_KEY)).toBeNull(); // …and no stale descriptor (consistent)
  });
});
