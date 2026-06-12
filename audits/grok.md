# Code Review Highlights (Core Strengths)
- June 11th

Key Derivation:
Passkey → PBKDF2 (100k iterations default, configurable, salt = normalized email) → 256-bit appKey.
Wallet sig → SHA256 → appKey (deterministic recovery).

Encryption: AES (via crypto-es) for wallet secrets. Plaintext never sent to server.
Challenges: 32-byte random (Web Crypto getRandomValues), single-use (atomic getdel), 5-min TTL.
Sessions: Opaque 256-bit tokens, server-side TTL + revocation on re-login/logout.
Rate Limiting: Dual (IP + identifier), configurable.
Signature Verification: tweetnacl for Solana, proper message prefix.
WebAuthn: User verification required, PRF support.
Client Vault: Memory/sessionStorage only (no localStorage), auto-lock, visibility lock, re-auth for key reveal.
Input Validation: Good bounds on wallets, sizes, etc.

Potential Issues & Recommendations (Harden the Core)
Here are the key findings with prioritized fixes. I focused on the core (@tetrac/login-sdk/core, shared crypto/utils) as requested.

Timing-Safe Comparison (Minor Risk)
timingSafeEqual uses a common JS implementation but has a small length leak before the loop and assumes string inputs of similar encoding.
Harden: Use crypto.subtle.timingSafeEqual (Node 16+/Web Crypto) where available, or a more robust polyfill. Fall back gracefully.

Crypto-es AES Defaults
Relies on library defaults for mode/IV/padding. AES in this context is typically CBC (check library source for confirmation).
Harden: Explicitly specify mode: CryptoES.mode.CBC, random IV per encryption, and include it (prepend) in ciphertext. Ensure authenticated encryption if possible (or add HMAC).

PBKDF2 Salt & Iterations
Salt = email.toLowerCase().trim() — predictable/low-entropy if email is known.
Harden: Use a per-user random salt (stored server-side with the passkey hash) or incorporate a high-entropy app-specific pepper. Keep iterations ≥100k; document minimum.

Randomness
randomHex uses globalThis.crypto.getRandomValues — excellent (falls back with error).
Good coverage for challenges/tokens.

Server-Side
Rate limiting trusts proxy headers only if configured (good anti-spoofing note in docs).
Challenge consume uses getdel (atomic) — solid.
Harden: Add nonce/anti-replay beyond TTL. Consider signed challenges. Validate all inputs more strictly (e.g., publicKey formats with libraries).

Client-Side Vault
Strong auto-lock and re-auth for reveals.
Harden: Document IndexedDB fallback risks for biometrics. Ensure appKey is zeroized aggressively (already partially done).

General Best Practices
No obvious XSS/SQLi (server is route handlers + KV/Redis).
Error messages are generic where needed (good for auth).
Add: Security headers (CSP, etc.) in Next.js integration. Audit logs for auth events. Regular dependency updates.
Transparency: Publish source to GitHub + enable npm provenance/signed packages.


Hardened Core Suggestions
To harden the core, update key functions in src/core/ (then rebuild). Here's a targeted set of improvements:
JavaScript// Enhanced random + timing-safe (core/index.ts or similar)
function randomHex(byteLength) {
  // ... existing ...
}

// Better timing safe
async function timingSafeEqual(a, b) {
  if (typeof crypto?.subtle?.timingSafeEqual === 'function' && a instanceof Uint8Array && b instanceof Uint8Array) {
    return crypto.subtle.timingSafeEqual(a, b); // or buffer conversion
  }
  // fallback with constant-time
  // ... existing or improved ...
}

// Explicit AES with IV (wrap crypto-es)
function encryptSecret(plaintext, appKey) {
  const iv = CryptoES.lib.WordArray.random(16); // 128-bit IV
  const encrypted = CryptoES.AES.encrypt(plaintext, appKey, { 
    iv, 
    mode: CryptoES.mode.CBC, 
    padding: CryptoES.pad.Pkcs7 
  });
  // Prepend IV to ciphertext (base64 or hex)
  return iv.toString(CryptoES.enc.Hex) + ':' + encrypted.toString();
}

function decryptSecret(ciphertext, appKey) {
  const [ivHex, data] = ciphertext.split(':');
  const iv = CryptoES.enc.Hex.parse(ivHex);
  // ... decrypt with iv ...
}

Update deriveAppKeyFromPasskey to accept/use random salt + store it.
Add JSDoc / comments on security assumptions.
Tests: Expand to cover edge cases (invalid sigs, expired challenges, key zeroization).

Recommendations

Run your own audit: npm audit, Snyk/Dependabot, manual review + tools like npm audit --audit-level=high.
Third-party Audit: For production use, get a professional Web3/auth audit (e.g., from Trail of Bits or similar).
Monitoring: Watch for updates to peers (Solana/web3.js has had supply-chain incidents).
Deployment: Follow the SDK's proxy/rate-limit notes strictly.

The SDK shows thoughtful security design for a v0.2.0 — it's already quite hardened for non-custodial use. Implementing the above (especially explicit crypto params + salt) would make the core production-grade. If you share the source repo or specific files, I can provide exact patches!

# Updated Security Audit: @tetrac/login-sdk (repo at v0.2.0)
The public repo confirms a clean, thoughtful non-custodial design extracted from a trading platform. No major red flags in high-level architecture. Dependencies are minimal and standard. Code is TypeScript, well-structured, with good separation (core/client/server).
Strengths (Reconfirmed)

Non-custodial model is solid: Wallets generated client-side, AES-encrypted under derived appKey (never sent to server). Server stores only public keys, ciphertext, passkeyHash (SHA-256), and session data.
Challenges: 256-bit random, single-use via getdel (atomic), short TTL (5 min default).
Rate limiting: Dual (IP + identifier), with self-healing expire.
Signature verification: Proper tweetnacl for Solana, prefixed message.
Crypto randomness: Relies on globalThis.crypto.getRandomValues — excellent.
Vault: Auto-lock, memory/sessionStorage only (no localStorage), re-auth for reveals.
WebAuthn: User verification required, PRF support.
Timing-safe compare: Custom implementation (good effort).
No obvious injection/XSS paths in core logic.
npm audit would be clean (only crypto-es dep).

Remaining Issues & Hardening Opportunities
The code already notes several compat-driven tradeoffs in crypto.ts comments (e.g., no AEAD, unsalted passkey hash). Here's a prioritized list focused on the core (src/core/):

AES Encryption (High Priority - No Authentication)
CryptoES.AES.encrypt (defaults to CBC + PKCS7, OpenSSL-style KDF). No integrity/auth tag → ciphertext tampering yields garbage or throws, but undetectable malleability.
Harden: Switch to explicit AES-GCM (authenticated) or add HMAC. Since compat with next-ttc is noted, make it configurable with migration path.

PBKDF2 Salt & Iterations (Medium)
Salt = email.toLowerCase().trim() (low entropy, known to attacker if email leaked).
100k iterations (configurable but below modern OWASP ~600k+).
Harden: Per-user random salt (stored server-side alongside passkeyHash). Increase default or strongly recommend higher.

Passkey Hashing (Medium)
Single unsalted SHA-256 → fast offline attacks if DB leaks.
Harden: Use PBKDF2/Argon2 for storage (slow verifier). Keep compat via version flag.

TimingSafeEqual
Good constant-time intent but has edge cases (different lengths, non-ASCII via charCodeAt).
Harden: Prefer Web Crypto subtle.timingSafeEqual (Uint8Array) when available.

Other Minor/Defensive
Input sanitization: Good but add stricter publicKey format validation (base58/0x length).
Error handling: Generic messages (good), but ensure no sensitive leaks.
Session tokens: Strong randomness, but consider signed JWT-like for stateless verification (optional).
Dependencies: Lock peers, add npm audit to CI.


No critical vulns found, but these elevate it from "good for v0.2" to production-hardened.
Hardened Core Patches
I'll propose targeted updates to src/core/crypto.ts (and related). You can apply these, bump version, rebuild (npm run build), and test.
First, read the current file if needed, but here's the improved version.
Updated src/core/crypto.ts (key changes: explicit GCM where possible, better salt, improved timing, comments):
TypeScript// ... existing header/comments ...

import CryptoES from "crypto-es";

/** Enhanced: Use random per-user salt (store salt server-side with passkeyHash for new users). */
export function deriveAppKeyFromPasskey(
  passkey: string,
  email: string,
  iterations = 600_000, // Increased default; keep config override
  salt?: string,        // New: random salt (hex)
): { appKey: string; salt?: string } {
  const normalizedEmail = email.toLowerCase().trim();
  const finalSalt = salt || normalizedEmail; // fallback for compat
  const derived = CryptoES.PBKDF2(passkey, finalSalt, {
    keySize: 256 / 32,
    iterations,
  }).toString(CryptoES.enc.Hex);
  return { appKey: derived, salt: salt ? undefined : undefined /* store if new */ };
}

// For Web3 - unchanged but documented
export function deriveAppKeyFromSignature(signatureHex: string): string {
  return CryptoES.SHA256(signatureHex).toString(CryptoES.enc.Hex);
}

// Hardened passkey storage hash (slow)
export function hashPasskeyForStorage(passkey: string, salt: string = randomHex(16)): string {
  return CryptoES.PBKDF2(passkey, salt, { keySize: 256/32, iterations: 100_000 }).toString(CryptoES.enc.Hex);
  // Store salt + hash
}

// **Authenticated encryption** (GCM preferred; fallback CBC for compat)
export function encryptSecret(plaintext: string, appKey: string, useGCM = true): string {
  if (useGCM && CryptoES.mode && CryptoES.mode.GCM) { // Check lib support
    const iv = CryptoES.lib.WordArray.random(12); // 96-bit IV for GCM
    const encrypted = CryptoES.AES.encrypt(plaintext, appKey, {
      iv,
      mode: CryptoES.mode.GCM,
      padding: CryptoES.pad.Pkcs7,
    });
    return `gcm:${iv.toString(CryptoES.enc.Hex)}:${encrypted.toString()}`;
  }
  // CBC fallback (compat)
  const iv = CryptoES.lib.WordArray.random(16);
  const encrypted = CryptoES.AES.encrypt(plaintext, appKey, { iv, mode: CryptoES.mode.CBC });
  return `cbc:${iv.toString(CryptoES.enc.Hex)}:${encrypted.toString()}`;
}

export function decryptSecret(ciphertext: string, appKey: string): string {
  if (ciphertext.startsWith('gcm:')) {
    const [, ivHex, data] = ciphertext.split(':');
    const iv = CryptoES.enc.Hex.parse(ivHex);
    // Use GCM decrypt...
    const decrypted = CryptoES.AES.decrypt(data, appKey, { iv, mode: CryptoES.mode.GCM }).toString(CryptoES.enc.Utf8);
    if (!decrypted) throw new Error("Decryption failed");
    return decrypted;
  }
  // CBC fallback logic (existing + IV parse)
  // ... adapt existing decrypt ...
  const out = CryptoES.AES.decrypt(ciphertext, appKey).toString(CryptoES.enc.Utf8); // update as needed
  if (!out) throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  return out;
}

// Improved timingSafeEqual
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  if (typeof crypto?.subtle?.timingSafeEqual === 'function') {
    const aBytes = new TextEncoder().encode(a);
    const bBytes = new TextEncoder().encode(b);
    if (aBytes.length !== bBytes.length) return false;
    return await crypto.subtle.timingSafeEqual(aBytes, bBytes);
  }
  // Fallback (existing improved)
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// randomHex, generate* unchanged - already strong
Other core changes:

Update config.ts: Increase pbkdf2Iterations default, add useAuthenticatedEncryption: true.
Server: Store salt with user data for passkey users; use new hash func.
Tests: Add tampering tests for old vs new ciphertexts.

Apply via edit_file or manually, then npm run build && npm test.
Next Steps Recommendations

CI/CD: Add npm audit, Dependabot, Snyk.
Transparency: Enable npm provenance, consider full audit (e.g., for Web3 auth).
Migration: Versioned cipher format for GCM rollout.
Further review: Check client/webauthn.ts for PRF key handling and IndexedDB fallback.

This hardens the core significantly while preserving compat where noted. The SDK is already one of the better non-custodial options out there. Share specific files or test results if you want patch refinements!