# Security

## Reporting a vulnerability

Report privately via [GitHub Security Advisories](https://github.com/tetrac-official/tetrac-login-sdk/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include a reproduction if you can — the storage conformance suite
(`@tetrac/login-sdk/storage/conformance`) is a convenient harness for backend-level findings.

Only the latest minor version receives fixes.

## Threat model

### What the server holds

A user record contains a public key, an optional email, an `authPublicKey`, and one AES-256-GCM
ciphertext per wallet. It contains **no key that can decrypt anything**.

- Wallet secrets are encrypted in the browser under an app key the server never receives.
- Sessions are stored as `SHA-256(token)` — both as the session key and as the record's pointer. A
  database read yields no replayable credential.
- The server holds no passkey, no passkey hash, and no password-equivalent. Authentication is
  proof-of-control of a key, verified by signature.

**A full database compromise does not yield wallet keys.** It yields ciphertext, public keys, and
email addresses. Offline attack against an email account's ciphertext requires guessing that
account's passkey through PBKDF2-HMAC-SHA256 at its pinned iteration count (600k by default).

### What the server cannot protect you from

**The app key is memory-only, and that boundary is the browser.**

The key that decrypts wallets is held in memory on a `Symbol.for()`-keyed global — never in
`localStorage`, never in `sessionStorage`, never sent over the network. `localStorage` holds only the
bearer token, the public key, and non-secret derivation parameters. It auto-locks after 15s idle and
on tab hide, page freeze, and bfcache restore.

That design defeats storage-scraping: an attacker who reads every key in `localStorage` finds no
decryption key. **It does not defeat script execution.** Any JavaScript running on your origin can
call the same signing and reveal APIs your own code calls, during the window the vault is unlocked.
This is true of every browser-based key system; no client-side design removes it.

Consequently, **your Content Security Policy is part of this SDK's security model.** Treat any route
that can sign or reveal as security-sensitive: no untrusted third-party scripts, no injected HTML.
The SDK holds up its end — there is no `eval`, `new Function`, `innerHTML`,
`dangerouslySetInnerHTML`, or `document.write` anywhere in the source, and no secret is ever logged.

### Email is not an identity claim

**The SDK performs no email verification, and none is intended.** In the email flow the address is
two things and nothing else:

1. **A KDF salt input** — the PBKDF2 salt is `SHA-256(appId : email)`.
2. **A storage index** — it maps to a public key within an `appId`.

It is not an assertion about who someone is. Users are expected to use anonymous or throwaway
addresses and generate their keypair client-side. The real credential is the **(email, passkey)
pair**; neither half alone identifies anyone, and the passkey never leaves the browser.

This has a consequence worth stating plainly: **the first caller to claim an address owns it on that
deployment.** An address already in use returns `409` at registration, and someone without the
matching passkey cannot log in — the same outcome as a wrong password, because that is
mechanically what it is. There is no recovery flow, because there is no account authority to appeal
to. A user who finds an address taken picks another.

**If your product needs email to mean identity, you must enforce that yourself** — gate `/register`
behind your own verification (magic link, OTP, SSO) before exposing it. The SDK will not do it for
you and does not pretend to.

### Keys that must never change

`appId` and `origin` are **app-key derivation input**, not labels.

- Email accounts derive from `SHA-256(appId : email)`.
- Web3 accounts sign a message embedding both `appId` and `origin`.

Changing either re-derives every app key on that path, and **existing encrypted wallets stop
decrypting**. There is no migration and no recovery — the ciphertext is the only copy of the private
key. Set both once, at launch, and treat them as immutable.

The most common way to hit this by accident is per-environment origins: a preview deployment on a
`*.vercel.app` URL derives different keys than production. Pin the production origin in every
environment that shares a database.

### Biometric requires WebAuthn PRF

There is no fallback mode. An authenticator without PRF throws `PrfUnavailableError` and registration
fails closed.

This is deliberate. The previous fallback stored a secret encrypted under a non-extractable
`CryptoKey` in IndexedDB — but non-extractability protects the key *bytes*, not the *decryption
capability*. A `CryptoKey` round-trips through IndexedDB with its usages intact, so any same-origin
script could decrypt that secret with no biometric prompt at all. Failing closed is honest; silently
downgrading was not.

PRF output is never persisted and requires a fresh assertion every time.

## Deployment requirements

The defaults are safe but not complete. Three settings are your responsibility, and
`createAuthHandlers` warns at boot about each while it is unset.

| Setting | Why it matters |
|---|---|
| `allowedAppIds` | Unset, any well-formed `appId` is accepted and silently creates a namespace. A client sending the wrong one registers into a **separate tenant under a different app key**, succeeds, and encrypts wallets the real deployment can never decrypt. |
| `appId` | Left at the default `"ttc"`, there is no cross-app key isolation — another deployment on the default derives the same keys from the same email. |
| `trustProxyHeaders` | Left `false`, the per-IP rate limit is skipped entirely and abuse controls fall back to keying on caller-supplied identifiers. Enable it **only** behind a proxy you operate — on a directly reachable app `x-forwarded-for` is caller-supplied, and trusting it is worse than leaving it off. |

Also:

- **Run the conformance suite against a real engine** if you implement a custom `AuthStore`. Backends
  that look correct fail in non-obvious ways — permanent rate-limit lockout, sessions accepted after
  expiry, replayable challenges, and lost writes that destroy wallet keys. The shipped Postgres,
  MySQL, SQLite, and Redis backends run it against real engines in CI.
- **Serve over HTTPS.** WebAuthn requires a secure context, and the origin binding assumes the origin
  is authentic.

## Known limitations

Stated so they are not mistaken for oversights.

- **`GET /search-wallet` is an account-existence oracle by design** — answering whether a public key
  is registered is the endpoint's purpose. Do not expose it if that answer is sensitive to you.
- **`POST /challenge` is not constant-time.** It answers an unknown email with a well-formed, unstored
  dummy challenge so the response carries no existence signal, but the real path performs storage work
  the dummy skips. A determined attacker can still separate them by latency. This closes the trivial
  read, not the side channel.
- **Sessions are bearer tokens.** Auth is header-based rather than cookie-based, so the API carries no
  ambient authority and is not CSRF-exposed — but anyone holding a token holds the session until the
  owner's next login revokes it or it expires.
- **The SDK cannot bound what your integration does with a revealed key.** `useExportKey` forces a
  fresh re-auth ceremony and auto-clears, but once plaintext is in your component state it is yours.

## Cryptography

For reviewers. All primitives are WebCrypto or [`@noble/hashes`](https://github.com/paulmillr/noble-hashes),
the SDK's only runtime dependency.

| Purpose | Construction |
|---|---|
| Wallet secret encryption | AES-256-GCM, fresh 96-bit CSPRNG IV per encryption, auth tag enforced on decrypt |
| App key (email) | PBKDF2-HMAC-SHA256, salt `SHA-256(appId : email)`, 100k/600k/1M by `securityLevel`, pinned per user |
| App key (Web3) | `SHA-256(signature)` over a message domain-bound by `appId` and `origin` |
| App key (biometric) | WebAuthn PRF output; HKDF-SHA-256 → AES-256-GCM for the unlock wrap key |
| Auth keypair | ed25519, seeded from `SHA-256("ttc-auth-v1:" + appKey)` — independent of the encryption key |
| Session tokens | 256-bit CSPRNG; storage sees only `SHA-256(token)` |
| Challenges | 256-bit CSPRNG, single-use, atomically consumed, constant-time compared |
