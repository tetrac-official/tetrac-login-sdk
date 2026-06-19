# Security Policy

`@tetrac/login-sdk` is a **non-custodial** authentication and wallet SDK: private keys are generated in
the browser and encrypted client-side before anything reaches a server. Cryptography is the product, so we
take reports seriously and document the design openly.

- **How the cryptography works:** [`docs/CRYPTO_SPEC.md`](./docs/CRYPTO_SPEC.md)
- **What we defend against (and what we don't):** [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md)
- **Integrator-facing summary:** the [Security model](./README.md#security-model) section of the README.

---

## Reporting a vulnerability

Report vulnerabilities through GitHub:
**[github.com/tetrac-official/tetrac-login-sdk/issues](https://github.com/tetrac-official/tetrac-login-sdk/issues)**.

- **Open a GitHub issue** titled `SECURITY: <short summary>`.
- For a sensitive or readily-exploitable finding, prefer GitHub's **private** vulnerability reporting
  instead of a public issue — *Security → Advisories → Report a vulnerability* — so users can be protected
  before details are public.
- Include: affected version(s) / commit, a description, reproduction steps or PoC, and the impact you
  believe it has. If you have a suggested fix, include it.

**What to expect**

| Stage | Target |
|---|---|
| Acknowledgement of your report | within 72 hours |
| Initial assessment + severity | within 7 days |
| Fix or mitigation for confirmed High/Critical issues | as fast as practical; coordinated disclosure |

We will credit reporters who want it. Please give us reasonable time to ship a fix before public
disclosure.

---

## Supported versions

This SDK is pre-1.0 and ships **clean breaks without migration scaffolding** (per maintainer policy):
breaking releases may change derived keys, ciphertext formats, or stored-record shapes, and affected
accounts re-register. Only the **latest published minor** receives security fixes.

| Version | Supported |
|---|---|
| latest `0.3.x` | ✅ |
| `< 0.3.0` | ❌ (upgrade) |

---

## Supported runtime / browser matrix

The SDK uses **Web Crypto exclusively** for at-rest encryption and a CSPRNG, with **no fallback to weak
primitives**. Code paths throw rather than silently degrading.

**Required everywhere**
- `globalThis.crypto.subtle` (Web Crypto `SubtleCrypto`) — AES-256-GCM, HKDF.
- `globalThis.crypto.getRandomValues` — CSPRNG. `randomHex()` throws if unavailable; there is **no**
  `Math.random` fallback.

**Server (`/server`, `/next`)**
- Node **≥ 18** (`engines.node`). Node 18+ exposes Web Crypto globally; for Node < 19 in unusual
  embeddings, supply a `globalThis.crypto` polyfill (e.g. `@peculiar/webcrypto`).

**Browser (`/client`, `/react`, `/ui`)**
- Modern evergreen browsers (Chromium, Firefox, Safari). **IE11 is not supported** and never will be.
- **Biometric (WebAuthn):** requires `PublicKeyCredential` +
  `isUserVerifyingPlatformAuthenticatorAvailable()`. The **PRF extension** is preferred; a non-extractable
  AES-GCM **gate** fallback is used when PRF is unavailable.
- **Biometric unlock & gate storage:** require **IndexedDB**.

If a required primitive is missing, the relevant feature throws — it does not fall back to insecure
behavior.

---

## The non-custodial responsibility model

Because keys are non-custodial and client-side, some risks **cannot** be closed in library code. They are
obligations on the integrator. See [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) §"Integrator
obligations" for the full list; the essentials:

- **Key loss = fund loss.** A user whose only factor is a single device authenticator (or who forgets the
  passkey/loses the wallet) is **unrecoverable**. Prompt users to register a backup factor.
- **XSS is the dominant client threat.** The session bearer token lives in `localStorage` (it must persist
  somewhere the page can read). Ship a strict **Content-Security-Policy**, Trusted Types, and SRI. The
  app/encryption key itself is memory-only and auto-locks, which limits — but does not eliminate — XSS
  exposure.
- **Email ownership & bot-gating.** The SDK does not verify email ownership; verify it (magic link / OTP)
  and bot-gate registration (CAPTCHA / Turnstile) **before** calling register.
- **Edge rate limiting.** The SDK rate-limits per target; pair it with volumetric/per-IP limiting at your
  edge (and set `trustProxyHeaders` / `trustedProxyHops` only behind a trusted proxy).
- **Set a unique, stable `appId`.** The default `"ttc"` provides **no** cross-app key isolation.
