// AuthClient.logout() must fire a best-effort POST /logout (server-side token
// revocation) BEFORE clearing local state — capturing the auth headers first —
// and must skip the network call entirely when there is no token. Runs in the
// node env with minimal window/storage/document shims so the session module's
// browser paths activate.
import { AuthClient } from "../src/client/authClient";
import { getAuthToken, getPublicKey, setSession } from "../src/client/session";

function storageShim(): Storage {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    get length() {
      return m.size;
    },
  } as Storage;
}

const fetchMock = jest.fn(async () => ({ ok: true, json: async () => ({}) }));

beforeAll(() => {
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  Object.defineProperty(globalThis, "localStorage", { value: storageShim(), configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: storageShim(), configurable: true });
  // configureVault binds a visibilitychange listener once window exists.
  Object.defineProperty(globalThis, "document", {
    value: { addEventListener: () => {}, visibilityState: "visible" },
    configurable: true,
  });
  Object.defineProperty(globalThis, "fetch", { value: fetchMock, configurable: true });
});

describe("AuthClient.logout() — best-effort server revocation", () => {
  beforeEach(() => {
    fetchMock.mockClear();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("POSTs /logout with the auth headers, then clears local state", async () => {
    const client = new AuthClient({ apiBaseUrl: "/api/auth" });
    setSession({ publicKey: "PubKey111", authToken: "tok-abc", appKey: "deadbeef" });
    expect(getAuthToken()).toBe("tok-abc");

    client.logout();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/auth/logout");
    expect(init.method).toBe("POST");
    // keepalive lets the revocation land even when logout coincides with page unload
    // (AUTHSESSION-10) — and unlike sendBeacon it still carries our auth headers.
    expect(init.keepalive).toBe(true);
    // Headers were captured BEFORE the local clear.
    expect((init.headers as Record<string, string>)["ttc-auth-token"]).toBe("tok-abc");
    expect((init.headers as Record<string, string>)["ttc-public-key"]).toBe("PubKey111");

    // Local state is gone immediately (no await on the network).
    expect(getAuthToken()).toBeNull();
    expect(getPublicKey()).toBeNull();
  });

  it("skips the network call when there is no session token", () => {
    const client = new AuthClient({ apiBaseUrl: "/api/auth" });
    client.logout();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still clears local state when the revocation request rejects", async () => {
    fetchMock.mockImplementationOnce(async () => {
      throw new Error("network down");
    });
    const client = new AuthClient({ apiBaseUrl: "/api/auth" });
    setSession({ publicKey: "PubKey222", authToken: "tok-def", appKey: "deadbeef" });

    expect(() => client.logout()).not.toThrow();
    expect(getAuthToken()).toBeNull();
    // Let the rejected promise settle; the .catch(() => {}) must swallow it.
    await new Promise((r) => setTimeout(r, 0));
  });
});
