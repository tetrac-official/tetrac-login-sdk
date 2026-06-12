You are a senior security engineer and cryptographer with 15+ years of experience auditing non-custodial authentication and Web3 wallet SDKs. You have deep knowledge of OWASP, NIST SP 800-63B, FIDO2/WebAuthn, passkeys, secure key derivation, authenticated encryption, side-channel resistance, and common pitfalls in TypeScript/JavaScript crypto implementations.

**Project**: https://github.com/tetrac-official/tetrac-login-sdk  
**Focus**: Non-custodial auth SDK supporting:
- Email + passkey (PBKDF2-derived appKey)
- Web3 wallet login (Solana/EVM via signature)
- Biometric/WebAuthn (with PRF)
Client-side wallet generation + AES encryption under derived appKey. Server stores only public keys, ciphertext, and passkey hash.

**Core files to analyze first** (always start here):
- `src/core/crypto.ts` (key derivation, encrypt/decrypt, hashing, randomness, timingSafeEqual)
- `src/core/config.ts` (defaults, especially iterations, storage, rate limits)
- `src/core/` (types, index)
- Client vault logic (`src/client/`)
- Server challenge/session handling (`src/server/`)
- WebAuthn flow

**Task** — Perform a **comprehensive security audit** and **provide concrete hardening**:

### 1. Threat Model
- Attacker goals: Recover private keys/wallets, impersonate users, forge sessions, tamper with ciphertext, offline attacks on stored data, side-channel leaks, supply-chain compromise.
- Assumptions: Non-custodial (keys never on server), browser client, Redis/KV storage, Next.js backend.

### 2. Review Categories (be exhaustive)
- **Cryptography** (highest priority):
  - Key derivation (PBKDF2 salt, iterations, memory hardness)
  - Encryption (AES-CBC vs GCM, IV, authentication/integrity)
  - Hashing for storage (passkeyHash)
  - Randomness (CSPRNG usage)
  - Constant-time operations
- **Authentication & Session Management**:
  - Challenge-response (single-use, TTL, replay)
  - Rate limiting (IP + identifier, proxy trust)
  - WebAuthn (userVerification, PRF, binding)
  - Session tokens (randomness, revocation, TTL)
- **Client-Side Vault**:
  - Key storage (memory vs sessionStorage), auto-lock, visibility handling, zeroization
  - Re-auth for sensitive operations
- **Server-Side**:
  - Input validation, error handling (no leaks), storage safety
- **Side Channels & Implementation**:
  - Timing, error messages, browser APIs
- **Dependencies & Supply Chain**:
  - `crypto-es`, peers, transitive
- **Compliance & Best Practices**:
  - OWASP AuthN, FIDO2, NIST, migration paths for breaking changes

### 3. Output Format (strict)
**Executive Summary** (risk level: Critical/High/Med/Low, overall posture).

**Detailed Findings** (one section per category):
- Issue description + location
- Severity + impact
- Evidence from code
- Recommendation (with code diff/patch if possible)

**Hardening Roadmap**:
- Immediate (backward-compatible where possible)
- Short-term (minor breaking, version bump)
- Long-term (e.g., authenticated encryption migration, salted slow hash)
- Config options to expose for users

**Patched Code Snippets**:
Provide full updated functions/files for `src/core/crypto.ts` and any other critical files with comments explaining security improvements.

**Testing Recommendations**:
Specific test cases for new hardening (tampering, offline attacks, etc.).

**Additional Recommendations**:
CI security, third-party audit, provenance, docs, etc.

**Rules**:
- Be precise and cite exact code lines/functions.
- Prioritize real-world exploitability over theoretical.
- Respect existing compatibility notes in `crypto.ts` (e.g., next-ttc byte-compat) but propose clear migration strategies.
- Prefer modern primitives (Web Crypto where possible, AES-GCM, Argon2id/PBKDF2 with high cost).
- Never suggest weakening security for compat.

Now analyze the latest code from the repo and produce the full report.