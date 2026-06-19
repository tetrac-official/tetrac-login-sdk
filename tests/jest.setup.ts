// Global test setup (runs before each suite, both node and jsdom envs).
// jsdom omits TextEncoder/TextDecoder and WebCrypto's subtle; back them with Node's.
// All assignments are guarded, so this is a no-op in the node environment (where
// these globals already exist).
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";

const g = globalThis as unknown as Record<string, unknown>;
if (!g.TextEncoder) g.TextEncoder = TextEncoder;
if (!g.TextDecoder) g.TextDecoder = TextDecoder;
if (!(g.crypto && (g.crypto as { subtle?: unknown }).subtle)) {
  Object.defineProperty(g, "crypto", { value: webcrypto, configurable: true });
}
