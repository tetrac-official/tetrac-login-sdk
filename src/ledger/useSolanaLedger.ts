// React hook owning a single Solana-Ledger device connection.
//
// SCOPE: this is the SDK layer — pure device I/O. It knows nothing about RPC
// endpoints, balances, or tokens (those are app concerns and were stripped from
// the original next-ttc hook). It exposes the proven connect / derive / confirm
// / sign primitives plus a `getSolanaSigner` factory that adapts a derived
// address into the SDK's wallet-adapter-shaped `SolanaSigner`.
//
// KEYLESS: the Ledger holds the Ed25519 private key. The only thing this hook
// ever receives from the device is a public address or a 64-byte signature —
// never key material. Nothing here is logged, persisted, or transmitted.
//
// The "use client" directive is applied to the bundled /ledger entry by the
// tsup banner pass (matching the /react entry), so it is not repeated per file.
import { useCallback, useMemo, useRef, useState } from "react";
import { PublicKey } from "@solana/web3.js";
import { createLedgerTransport, mapLedgerDeviceError } from "./transport.js";
import { createLedgerSolanaSigner } from "./solanaSigner.js";
import type { SolanaSigner } from "../react/useSolanaSigner.js";

/** One address derived from the device, identified by its BIP-32 path. */
export interface LedgerDerivedAddress {
  /** BIP-32 path including the `m/` prefix, e.g. `m/44'/501'/0'/0'`. */
  path: string;
  /** base58 public address (safe to display/persist — never key material). */
  address: string;
  /** Convenience web3.js handle for the same address. */
  publicKey: PublicKey;
  /** Account index within the standard `m/44'/501'/i'/0'` derivation. */
  index: number;
}

/** Identity of a derived account used to build a {@link SolanaSigner}. */
export interface LedgerSignerTarget {
  /** BIP-32 path (with or without the `m/` prefix). */
  path: string;
  /** base58 address expected at `path` — becomes the signer's `publicKey`. */
  address: string;
}

export interface UseSolanaLedgerReturn {
  isConnecting: boolean;
  isConnected: boolean;
  isDerivingAddresses: boolean;
  error: string | null;
  /** Human-readable device status, suitable for a status line. */
  deviceStatus: string;
  /** Addresses derived so far via {@link deriveAddresses}. */
  addresses: LedgerDerivedAddress[];
  /** Open the transport (WebUSB→WebHID) and confirm the Solana app is open. */
  connect: () => Promise<void>;
  /** Close the transport and reset all state. */
  disconnect: () => Promise<void>;
  /** Derive the first `count` accounts on `m/44'/501'/i'/0'` (no on-device prompt). */
  deriveAddresses: (count?: number) => Promise<void>;
  /**
   * Re-derive ONE path WITH on-device display so the Ledger shows the address
   * and the user physically approves it. Returns the device-derived base58
   * address (public). Throws on rejection (fail-closed).
   */
  confirmAddress: (path: string) => Promise<string>;
  /**
   * Sign a serialized transaction MESSAGE at `path`. Returns the bare 64-byte
   * device signature. Prefer {@link getSolanaSigner} for end-to-end signing.
   */
  signTransaction: (path: string, txMessage: Uint8Array) => Promise<Uint8Array>;
  /**
   * Sign a pre-serialized Solana off-chain message at `path`. Returns the bare
   * 64-byte signature. Prefer the signer's `signMessage`, which builds the
   * off-chain envelope for you.
   */
  signOffchainMessage: (path: string, msgBuffer: Uint8Array) => Promise<Uint8Array>;
  /** Read the Solana app config (version + whether blind signing is enabled). */
  getAppConfig: () => Promise<{ version: string; blindSigningEnabled: boolean }>;
  /**
   * Adapt a derived account into a wallet-adapter-shaped {@link SolanaSigner}
   * — a drop-in for `useSolanaSigner(wallet)`. Each signing call prompts the
   * device; rejection throws. Throws immediately if `target` contradicts the
   * derived set (address/path disagree).
   *
   * Returns a NEW signer object on every call, so memoize it when passing into
   * memo-sensitive consumers (Anchor, wallet-adapter):
   * `const signer = useMemo(() => getSolanaSigner(t), [getSolanaSigner, t.path, t.address])`.
   */
  getSolanaSigner: (target: LedgerSignerTarget) => SolanaSigner;
}

/** Strip the `m/` BIP-32 prefix the Ledger app does not expect. */
function toLedgerPath(path: string): string {
  return path.startsWith("m/") ? path.slice(2) : path;
}

export function useSolanaLedger(): UseSolanaLedgerReturn {
  const [isConnecting, setIsConnecting] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [isDerivingAddresses, setIsDerivingAddresses] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [addresses, setAddresses] = useState<LedgerDerivedAddress[]>([]);
  const [deviceStatus, setDeviceStatus] = useState("Disconnected");

  // The live transport + Solana app instance. `any` because hw-app-solana is an
  // optional peer dep loaded lazily — we never import its type at module load.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transportRef = useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const solanaAppRef = useRef<any>(null);
  // Re-entrancy guard for connect(): React state lags a render, so a ref is the
  // only reliable way to reject a second connect() before the first resolves.
  const isConnectingRef = useRef(false);
  // Always-latest mirror of `addresses` so getSolanaSigner can validate a target
  // against the derived set without taking `addresses` as a callback dependency.
  const addressesRef = useRef<LedgerDerivedAddress[]>(addresses);
  addressesRef.current = addresses;

  // Tear down to a clean disconnected state. Shared by disconnect() and the
  // transport "disconnect" event (physical unplug / USB permission revocation).
  const resetConnection = useCallback((status: string) => {
    transportRef.current = null;
    solanaAppRef.current = null;
    setIsConnected(false);
    setDeviceStatus(status);
  }, []);

  const connect = useCallback(async () => {
    // Reject overlapping connects (re-entrancy guard, ref not state).
    if (isConnectingRef.current) return;
    isConnectingRef.current = true;
    setIsConnecting(true);
    setError(null);
    setDeviceStatus("Connecting…");

    // Close any prior transport before opening a new one (double-connect leak).
    try {
      await transportRef.current?.close();
    } catch {
      // Ignore — the prior handle may already be gone.
    }
    transportRef.current = null;
    solanaAppRef.current = null;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let transport: any = null;
    try {
      transport = await createLedgerTransport();
      const Solana = (await import("@ledgerhq/hw-app-solana")).default;
      const solanaApp = new Solana(transport);
      // Probe the connection (and surface "app not open"/"locked") without a prompt.
      await solanaApp.getAddress("44'/501'/0'");
      // Reflect physical unplug / USB-permission revocation: the transport emits
      // "disconnect", after which the handle is dead — drop refs and mark closed
      // so we never report a stale "connected" state with a torn-down transport.
      transport.on?.("disconnect", () => resetConnection("Disconnected"));
      transportRef.current = transport;
      solanaAppRef.current = solanaApp;
      setIsConnected(true);
      setDeviceStatus("Connected — Solana app open");
    } catch (err: unknown) {
      // Release the open transport on any probe/setup failure (transport leak).
      try {
        await transport?.close();
      } catch {
        // Ignore close errors during cleanup.
      }
      transportRef.current = null;
      solanaAppRef.current = null;
      const message = mapLedgerDeviceError(err, "Connection");
      setError(message);
      setDeviceStatus(message);
      setIsConnected(false);
    } finally {
      isConnectingRef.current = false;
      setIsConnecting(false);
    }
  }, [resetConnection]);

  const disconnect = useCallback(async () => {
    try {
      await transportRef.current?.close();
    } catch {
      // Ignore close errors — the handle may already be gone.
    }
    resetConnection("Disconnected");
    setAddresses([]);
    setError(null);
  }, [resetConnection]);

  const deriveAddresses = useCallback(async (count = 5) => {
    if (!solanaAppRef.current) {
      setError("Ledger not connected.");
      return;
    }
    setIsDerivingAddresses(true);
    setError(null);
    setDeviceStatus("Deriving addresses…");
    try {
      const solanaApp = solanaAppRef.current;
      const derived: LedgerDerivedAddress[] = [];
      for (let i = 0; i < count; i++) {
        const path = `44'/501'/${i}'/0'`;
        const result = await solanaApp.getAddress(path);
        const publicKey = new PublicKey(result.address);
        derived.push({ path: `m/${path}`, address: publicKey.toBase58(), publicKey, index: i });
      }
      setAddresses(derived);
      setDeviceStatus("Connected — Addresses derived");
    } catch (err: unknown) {
      const message = mapLedgerDeviceError(err, "Address derivation");
      setError(message);
      setDeviceStatus(message);
    } finally {
      setIsDerivingAddresses(false);
    }
  }, []);

  const confirmAddress = useCallback(async (path: string): Promise<string> => {
    if (!solanaAppRef.current) throw new Error("Ledger not connected.");
    setDeviceStatus("Confirm the address on your Ledger…");
    try {
      // display=true → the device renders the address and waits for approval.
      const result = await solanaAppRef.current.getAddress(toLedgerPath(path), true);
      const confirmed = new PublicKey(result.address).toBase58();
      setDeviceStatus("Connected — Address confirmed");
      return confirmed;
    } catch (err: unknown) {
      const message = mapLedgerDeviceError(err, "Address confirmation");
      setDeviceStatus(message);
      throw new Error(message);
    }
  }, []);

  const signTransaction = useCallback(async (path: string, txMessage: Uint8Array): Promise<Uint8Array> => {
    if (!solanaAppRef.current) throw new Error("Ledger not connected.");
    setDeviceStatus("Confirm transaction on Ledger…");
    try {
      // hw-app-solana wraps the buffer with Buffer.concat (which accepts a
      // Uint8Array), so we pass the message bytes directly — no global Buffer.
      const { signature } = await solanaAppRef.current.signTransaction(toLedgerPath(path), txMessage);
      setDeviceStatus("Connected — Transaction signed");
      return signature;
    } catch (err: unknown) {
      const message = mapLedgerDeviceError(err, "Transaction");
      setDeviceStatus(message);
      throw new Error(message);
    }
  }, []);

  const signOffchainMessage = useCallback(
    async (path: string, msgBuffer: Uint8Array): Promise<Uint8Array> => {
      if (!solanaAppRef.current) throw new Error("Ledger not connected.");
      setDeviceStatus("Confirm message on Ledger…");
      try {
        const { signature } = await solanaAppRef.current.signOffchainMessage(toLedgerPath(path), msgBuffer);
        setDeviceStatus("Connected — Message signed");
        return signature;
      } catch (err: unknown) {
        const message = mapLedgerDeviceError(err, "Message signature");
        setDeviceStatus(message);
        throw new Error(message);
      }
    },
    [],
  );

  const getAppConfig = useCallback(async () => {
    if (!solanaAppRef.current) throw new Error("Ledger not connected.");
    const cfg = await solanaAppRef.current.getAppConfiguration();
    return { version: cfg.version, blindSigningEnabled: cfg.blindSigningEnabled };
  }, []);

  const getSolanaSigner = useCallback(
    (target: LedgerSignerTarget): SolanaSigner => {
      // Defense-in-depth: if the target appears in the derived set, its address
      // and path must agree — catches stale/hand-built targets before signing.
      const normalizedPath = target.path.startsWith("m/") ? target.path : `m/${target.path}`;
      const byAddress = addressesRef.current.find((a) => a.address === target.address);
      if (byAddress && byAddress.path !== normalizedPath) {
        throw new Error(
          `Ledger signer target mismatch: address ${target.address} was derived at ${byAddress.path}, not ${normalizedPath}.`,
        );
      }
      const byPath = addressesRef.current.find((a) => a.path === normalizedPath);
      if (byPath && byPath.address !== target.address) {
        throw new Error(
          `Ledger signer target mismatch: path ${normalizedPath} derives ${byPath.address}, not ${target.address}.`,
        );
      }
      return createLedgerSolanaSigner({
        address: target.address,
        path: target.path,
        signTransaction,
        signOffchainMessage,
      });
    },
    [signTransaction, signOffchainMessage],
  );

  return useMemo(
    () => ({
      isConnecting,
      isConnected,
      isDerivingAddresses,
      error,
      deviceStatus,
      addresses,
      connect,
      disconnect,
      deriveAddresses,
      confirmAddress,
      signTransaction,
      signOffchainMessage,
      getAppConfig,
      getSolanaSigner,
    }),
    [
      isConnecting,
      isConnected,
      isDerivingAddresses,
      error,
      deviceStatus,
      addresses,
      connect,
      disconnect,
      deriveAddresses,
      confirmAddress,
      signTransaction,
      signOffchainMessage,
      getAppConfig,
      getSolanaSigner,
    ],
  );
}
