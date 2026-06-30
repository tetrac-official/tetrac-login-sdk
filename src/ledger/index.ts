// Public surface of the Ledger module (@tetrac/login-sdk/ledger).
//
// Solana hardware-wallet support. The heavy @ledgerhq packages are OPTIONAL
// peer deps loaded lazily inside the hook, so importing this subpath costs
// nothing until a Ledger flow actually runs. Keeping it on its own subpath
// (not /react) means non-Ledger consumers never pull @ledgerhq into their bundle.
export {
  useSolanaLedger,
  type UseSolanaLedgerReturn,
  type LedgerDerivedAddress,
  type LedgerSignerTarget,
} from "./useSolanaLedger.js";
export { createLedgerSolanaSigner, type LedgerSolanaSignerDeps } from "./solanaSigner.js";
export { createLedgerTransport, mapLedgerDeviceError } from "./transport.js";
// The off-chain envelope encoder now lives in /core (shared with the server
// verifier); re-exported here so /ledger consumers keep a single import surface.
export { encodeOffchainMessage, type EncodeOffchainMessageOptions } from "../core/offchainMessage.js";
// Re-export the signer shape so a consumer can type a Ledger signer without
// reaching into the /react subpath.
export type { SolanaSigner } from "../react/useSolanaSigner.js";
