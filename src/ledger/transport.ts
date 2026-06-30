// Ledger transport factory + device-error mapping — the two browser-only
// primitives every Ledger flow needs, with zero app-specific dependencies.
//
// SECURITY CONTRACT: this module NEVER instantiates an app class (Solana/Eth)
// and never touches key material. It returns only a Transport handle and
// human-readable error strings. ("use client" is applied to the bundled
// /ledger entry by the tsup banner pass, so it is not repeated per file.)

// Type-only import (erased at build) so this module pulls in no runtime
// @ledgerhq code at import time — the concrete transports load lazily inside
// createLedgerTransport via dynamic import, keeping them out of the SSR bundle.
import type Transport from "@ledgerhq/hw-transport";

/**
 * Open a Ledger {@link Transport} over WebUSB, falling back to WebHID.
 *
 * Tries WebUSB first (broadest support on Chrome/Edge); on any throw it falls
 * back to WebHID; if both throw it raises a single actionable error. Returns a
 * bare Transport handle — the caller wraps it in `new Solana(transport)`; this
 * factory deliberately does not, so it can never reach a signing API.
 *
 * Both transports are imported dynamically so the browser-only modules
 * (which reference `navigator.usb` / `navigator.hid`) never execute during SSR.
 */
export async function createLedgerTransport(): Promise<Transport> {
  let transport: Transport;
  try {
    const TransportWebUSB = (await import("@ledgerhq/hw-transport-webusb")).default;
    transport = await TransportWebUSB.create();
  } catch {
    try {
      const TransportWebHID = (await import("@ledgerhq/hw-transport-webhid")).default;
      transport = await TransportWebHID.create();
    } catch {
      throw new Error(
        "Could not connect via WebUSB or WebHID. Use Chrome or Edge, and ensure your Ledger is connected and unlocked.",
      );
    }
  }
  return transport;
}

/**
 * Translate a thrown Ledger error into a user-facing, action-oriented string.
 *
 * Ledger surfaces failures as `Error`s whose `.message` embeds a status word
 * (e.g. `0x6e01`, `0x6985`) or a textual hint (`Locked device`). We match on
 * substrings — coded forms on the raw message, worded forms case-insensitively
 * since firmware varies the casing — and translate. `actionLabel` names the
 * operation in the rejection message (e.g. "Transaction was rejected …").
 *
 * Returns only a static guidance string — never device data or a signature.
 *
 * @param err         the unknown error thrown by an @ledgerhq call
 * @param actionLabel a short noun phrase for the action, used in rejection text
 */
export function mapLedgerDeviceError(err: unknown, actionLabel: string): string {
  const message = err instanceof Error ? err.message : "Ledger device error occurred";
  const lower = message.toLowerCase();

  // 0x6e01 / 0x6e00 — the required app (Solana) is not open on the device.
  if (message.includes("0x6e01") || message.includes("0x6e00")) {
    return "Please open the Solana app on your Ledger device.";
  }
  // Locked device — the real thrown text is "Ledger device: Locked device
  // (0x5515)". Match the lowercased word AND the status word so both forms hit.
  if (lower.includes("locked") || message.includes("0x5515")) {
    return "Please unlock your Ledger device.";
  }
  // 0x6985 / "denied" / "rejected" — the user declined the on-device prompt.
  if (message.includes("0x6985") || lower.includes("denied") || lower.includes("rejected")) {
    return `${actionLabel} was rejected on the Ledger device.`;
  }
  // BLIND_SIGNATURE_REQUIRED — hw-app-solana throws the literal "Missing a
  // parameter. Try enabling blind signature in the app" (no 26632/0x6808 in the
  // text), so match the worded forms in addition to the coded ones.
  if (
    lower.includes("blind sign") ||
    lower.includes("blind signature") ||
    lower.includes("missing a parameter") ||
    message.includes("26632") ||
    message.includes("0x6808")
  ) {
    return "Enable Blind Signing in the Ledger Solana app and retry.";
  }
  // Device went away mid-operation (physical unplug / USB-permission revocation):
  // @ledgerhq throws DisconnectedDevice / DisconnectedDeviceDuringOperation.
  if (lower.includes("disconnect")) {
    return `${actionLabel} could not complete — the Ledger was disconnected. Reconnect and try again.`;
  }
  // No known status word matched — surface the raw message (it may already be
  // our own actionable string, e.g. the WebUSB/WebHID failure text above).
  return message;
}
