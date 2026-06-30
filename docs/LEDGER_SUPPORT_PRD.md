# Feature PRD — Hardware-wallet (Ledger) login support (`0.5.0`)

Enable **Ledger** (and any hardware wallet that signs via Solana *off-chain messages*) to be used as a
Web3 login identity in `@tetrac/login-sdk`. Today a Ledger user can connect and physically sign, but auth
fails with **`401 Invalid credentials`**, and even if auth were patched the encryption-key derivation is
unsafe for hardware wallets. This PRD defines a path that makes Ledger login both **functional** and
**non-custodially safe** (no silent fund loss).

- **Status:** 📝 Proposed. Not yet implemented.
- **Shape:** **Additive + wire-protocol change.** Adds an optional `signEncoding` hint to the wallet
  auth/connect/register requests and a server-side off-chain-envelope verifier. Existing software-wallet
  and email/biometric flows are unchanged and bit-for-bit compatible. Needs a **fresh security audit**
  (§9) because it touches signature verification (§5.1 of `CRYPTO_SPEC.md`) and app-key derivation
  (§2.2).
- **Driver:** Product — hardware-wallet users (the security-conscious cohort most likely to adopt a
  self-custody social app) currently cannot log in on Shyft, ttc.box, or any SDK consumer.
- **Reproduction:** `connectWallet` with a Phantom account backed by a Ledger → device prompts and signs →
  server returns `401 Invalid credentials`. Reproduces identically across every SDK consumer, confirming
  the defect is in the SDK, not the app.
- **Verification (planned):** golden-vector tests captured from real Ledger hardware (§8), `tsc --noEmit`
  + Prettier clean, full Jest suite green, plus a manual device matrix (Nano S/S+/X via Phantom &
  Solflare).

---

## 1. Motivation — why Ledger fails today

A software wallet signs the **raw UTF-8 bytes** of the message it is handed. A Ledger **never** does. The
Ledger Solana app only signs **Solana off-chain messages**: the wallet wraps the text in a domain-bound
envelope and the device signs *that*. So the returned signature is valid — but over different bytes than
the SDK verifies.

### 1.1 The `401` failure chain (auth signature)

1. `walletHandshake()` asks the wallet to sign `walletLoginMessage(challenge)` =
   `"Sign this message to verify wallet ownership: <64-hex>"`
   ([`src/client/authClient.ts:258-271`](../src/client/authClient.ts#L258-L271)).
2. The server verifies with `nacl.sign.detached.verify(rawMessageBytes, sig, pubKey)` over the **raw**
   bytes ([`src/server/signature.ts:24-37`](../src/server/signature.ts#L24-L37)).
3. Software Phantom signs the raw bytes → verifies → ✅.
4. Ledger signs the **off-chain envelope** (below) → `nacl.verify(rawBytes, …)` is `false` →
   `sigValid = false` → `error("Invalid credentials", 401)`
   ([`src/server/routes.ts:410-417`](../src/server/routes.ts#L410-L417)). The same `verifySolanaSignature`
   call gates `login-wallet`, `connect-wallet`, **and** the wallet-`register` branch
   ([`routes.ts:279`](../src/server/routes.ts#L279)), so every wallet entry point fails identically.

### 1.2 The Solana off-chain message envelope (version 0)

The signed pre-image is **not** the message — it is:

| Offset | Field | Size | Value |
|---|---|---|---|
| 0 | Signing domain | 16 | `\xff` + `"solana offchain"` (`FF736F6C616E61206F6666636861696E`) |
| 16 | Header version | 1 | `0` |
| 17 | Application domain | 32 | arbitrary (Phantom: 32 zero bytes) |
| 49 | Message format | 1 | `0` ASCII \| `1` UTF-8 ≤1232 \| `2` UTF-8 ≤65535 |
| 50 | Signer count | 1 | `≥1` (typically `1`) |
| 51 | Signers | `count×32` | ed25519 pubkey(s) — **the signer's own pubkey** |
| 51+n | Message length | 2 | `u16` little-endian |
| 53+n | Message body | N | the actual text |

A **"legacy"/compact** header (no application domain, no signer list) and a newer **sRFC-38 "v1"** header
also exist; the Ledger SDK *cascades* `v1 → v0 → legacy`, falling back when the device rejects a header
with `6a81`. So the exact pre-image depends on device firmware and adapter version (§3.2).

**Message-format support on hardware** (from the Solana proposal):

| Format | Encoding | Hardware-wallet support |
|---|---|---|
| 0 | Restricted ASCII (`0x20`–`0x7e` only) | ✅ Yes |
| 1 | UTF-8 (≤1232) | ⚠️ **Blind-sign only** |
| 2 | UTF-8 (>1232) | ❌ No |

### 1.3 The deeper, dangerous problem — app-key derivation (silent fund loss)

The `401` is only the first symptom. The SDK derives the **encryption app key** — the AES key for *all* of
a user's wallet private keys — from a second signature over a **fixed** message:

```
keySig = sign( walletAppKeyMessage(appId) )                 // src/client/authClient.ts:265
appKey = hex( SHA-256( hex(keySig) ) )                       // deriveAppKeyFromSignature (crypto.ts)
```

For a software wallet this is safe: ed25519 is deterministic, so the same wallet re-derives the same
`appKey` forever (`CRYPTO_SPEC.md` §2.2). For a Ledger this assumption **breaks in two ways**:

- **(a) The message can't cleanly sign.** `walletAppKeyMessage` contains newlines (`\n\n`,
  [`src/core/index.ts:18-30`](../src/core/index.ts#L18-L30)). `0x0a` is outside printable ASCII, forcing
  **format 1 (UTF-8)** → *blind-sign only* on Ledger. Users without blind signing enabled are rejected
  by the device. (The login message is fine — a hex challenge is pure ASCII → format 0.)
- **(b) The signature is not stable across firmware.** The Ledger signs the *envelope*, whose version is
  chosen by the `v1 → v0 → legacy` fallback cascade. A firmware or wallet-adapter update that changes the
  winning version changes the pre-image → changes `keySig` → changes `appKey` → **the user's existing
  wallets no longer decrypt.** That is silent, permanent loss of the embedded signing/funds wallets, not a
  recoverable login error.

Any Ledger design that ignores (b) is unacceptable. This PRD makes envelope drift a **recoverable
re-enrollment**, never a loss.

---

## 2. Goals / Non-goals

### Goals
1. A Ledger-backed wallet (via Phantom/Solflare/Backpack) can **register and log in** through
   `connectWallet` / `loginWithWallet` / `registerWithWallet` without a `401`.
2. The off-chain-envelope verification is **cryptographically sound** — it accepts only a signature whose
   pre-image embeds the server's single-use challenge; it never widens what counts as a valid proof.
3. A Ledger user's embedded wallets remain decryptable **across firmware/adapter upgrades** — envelope
   drift triggers a transparent re-enrollment, **never** data loss.
4. No blind-sign requirement for the common path (use format-0/ASCII messages for new hardware accounts).
5. **Zero regression** for software-wallet, email, and biometric accounts — byte-identical behavior and
   storage.

### Non-goals
- Native Ledger transport (WebHID/WebUSB) inside the SDK. We rely on the **injected wallet** (Phantom et al.)
  to drive the device, exactly as the SDK does today for software wallets.
- EVM/secp256k1 hardware wallets. External wallet login stays **Solana-only** (`CRYPTO_SPEC.md` §8).
- Changing the at-rest ciphertext format (AES-256-GCM, `CRYPTO_SPEC.md` §3) — unchanged.
- Server-side key custody, escrow, or recovery (`CRYPTO_SPEC.md` §8) — the recovery factor in §4 is
  **client-held**, consistent with the non-custodial model.

---

## 3. Design — Part 1: off-chain-aware auth verification (fixes the `401`)

### 3.1 Wire change — a verifiable encoding hint

The client adds an optional `signEncoding` descriptor to the wallet auth payloads
(`login-wallet`, `connect-wallet`, and the wallet `register` branch):

```ts
type SignEncoding =
  | { kind: "raw" }                                   // software wallet (default; today's behavior)
  | { kind: "offchain"; version: 0 | 1 | "legacy"; format: 0 | 1; appDomain?: string /* 32-byte hex */ };
```

This is a **hint, not a trust boundary.** The server uses it only to decide *which pre-image to
reconstruct*. The cryptographic check is unchanged in spirit: the signature must verify against a
reconstructed pre-image **that embeds the server-issued challenge**. A forged or wrong hint simply
produces a pre-image the signature does not match → `false`. An attacker gains nothing by lying about the
encoding. (Absent hint → server defaults to `raw`, preserving today's exact path.)

### 3.2 Server reconstruction & verification

Extend `verifySolanaSignature` ([`src/server/signature.ts`](../src/server/signature.ts)) to verify against
a **reconstructed pre-image**. The server already knows everything needed for v0: the message
(`walletLoginMessage(challenge)`) and the signer pubkey (`body.publicKey`).

```
function preimage(message, signerPk, enc):
  if enc.kind == "raw": return utf8(message)
  // offchain:
  format = enc.format ?? (isPrintableAscii(message) ? 0 : 1)
  body   = utf8(message)
  switch enc.version:
    "legacy": return DOMAIN16 ++ [0] ++ [format] ++ u16le(body.len) ++ body
    0:        return DOMAIN16 ++ [0] ++ (enc.appDomain ?? ZERO32) ++ [format] ++ [1] ++ signerPk32 ++ u16le(body.len) ++ body
    1:        return /* sRFC-38 v1 layout, locked by golden vector (§8) */

verifySolanaSignature(pk, sigHex, challenge, enc?):
  msg = walletLoginMessage(challenge)
  if enc: return nacl.verify(preimage(msg, pk32, enc), sig, pk32)
  // No/unknown hint → try raw, then a bounded set of known encodings (defense in depth):
  for cand in [raw, {offchain,v0,fmt0}, {offchain,legacy,fmt0}, {offchain,v1,fmt0}]:
    if nacl.verify(preimage(msg, pk32, cand), sig, pk32): return true
  return false
```

- **Bounded brute-force.** With no hint the server tries `raw` + a small fixed set of known encodings
  (all format-0 for the login message). This keeps old/hintless clients working and absorbs adapter
  differences. The set is a constant — never client-controlled — so it can't be expanded into a DoS.
- **The exact bytes are locked by golden vectors, not by this pseudo-code.** §1.2's layout is the published
  spec, but the *actual* bytes Phantom-over-Ledger emits must be confirmed empirically and frozen as test
  vectors (§8). Implementation captures one real signature per (wallet, device, version) and asserts the
  reconstruction matches **before** shipping.
- **Challenge binding is preserved.** Because the reconstructed body is exactly
  `walletLoginMessage(challenge)` and the challenge is single-use (`consumeChallenge`,
  [`src/server/challenge.ts`](../src/server/challenge.ts)), envelope support does not weaken replay
  protection.

### 3.3 Client change — detect & describe the encoding

The injected wallet does the device I/O; the SDK's job is to **label** what was signed. Detection options,
in order of preference:

1. **Adapter signal.** Phantom/wallet-standard expose the connected account's hardware status on some
   versions; when available, set `signEncoding.kind = "offchain"`.
2. **Round-trip probe.** After obtaining the auth signature, the client verifies it locally against the
   `raw` pre-image (cheap, `tweetnacl`). If `raw` fails, it tries the known envelopes, and reports the one
   that verifies. This is robust and adapter-agnostic — the client *proves* the encoding to itself before
   hinting the server.

The probe (option 2) is the recommended default because it needs no wallet-specific capability detection.
It lives in `walletHandshake` ([`src/client/authClient.ts:258-271`](../src/client/authClient.ts#L258-L271)),
which already holds both the message and signature.

---

## 4. Design — Part 2: envelope-drift-safe app key (prevents fund loss)

The fix in §3 makes a Ledger *log in*. This section makes its wallets **stay decryptable**. We stop
treating the Ledger signature as a guaranteed-stable key source and instead use it to **wrap** a stable
master key, with a mandatory recovery factor.

### 4.1 Ledger-safe key message (no blind signing)

Introduce a **format-0, newline-free** app-key message used **only** for hardware-wallet accounts:

```
walletAppKeyMessageHw(appId) =
  "Unlock your encrypted TTC wallet keys. Only sign on a site you trust. App: " + appId
```

- Pure printable ASCII → **format 0** → signs on Ledger with **no blind-signing**.
- Pin a per-account `keyMsgVersion` (`"v1-nl"` for the legacy newline message, `"v2-ascii"` for the new
  one) in `UserData` so the client always re-derives with the *same* message the account was created with.
  Software accounts keep `v1-nl` → **bit-for-bit unchanged**.

### 4.2 Master-key wrapping with a recovery factor

At Ledger registration:

```
master   = getRandomValues(32)                       // the REAL AES key for this account's wallets
kdk      = HKDF-SHA256(ikm = SHA-256(keySig), info = "ttc-hw-wrap-v1")   // key-derivation key from the Ledger sig
wrapSig  = AES-256-GCM(kdk, master)                   // primary wrap — convenience path
wrapRec  = AES-256-GCM(recoveryKEK, master)           // mandatory recovery wrap
```

- `master` (not the signature hash) becomes the app key that encrypts the wallet bundle (`CRYPTO_SPEC.md`
  §3 unchanged — only the *source* of the key changes for HW accounts).
- **`wrapSig`** is the fast path: a normal login re-signs, re-derives `kdk`, unwraps `master`.
- **`wrapRec`** is the safety net for envelope drift. The recovery KEK comes from one of:
  - the existing **biometric-unlock** layer (`CRYPTO_SPEC.md` §4) — reuse `enableBiometricUnlock`, or
  - a **downloadable recovery code** (24-word / base58 blob the user saves), HKDF-stretched to an AES key.
- **Drift recovery flow:** if `wrapSig` unwrap fails on login (envelope changed → wrong `kdk`), the client
  falls back to `wrapRec`, recovers `master`, then **re-wraps** `wrapSig` under the *new* signature. The
  user is prompted once ("re-confirm on your Ledger") and never loses access. Envelope drift becomes a
  silent re-enrollment.

Both wrap blobs are non-secret-at-rest ciphertext (like every `EncryptedWallet`) and may be stored
server-side alongside the user record or client-side; storage-scraping XSS reads ciphertext it cannot
unwrap.

### 4.3 Why not just derive the key from the signature (today's approach)?

Because §1.3(b): the signature is only stable *per device, per firmware/adapter version*. Shipping a
key-from-signature path with no recovery factor would create a fund-loss landmine that detonates on a
routine Ledger firmware update. The recovery wrap is therefore **mandatory**, not optional, for HW
accounts.

---

## 5. API & type surface

| Area | Change | File |
|---|---|---|
| Request types | add optional `signEncoding` to login-wallet / connect-wallet / register payloads | [`src/core/types.ts`](../src/core/types.ts) |
| Verifier | `verifySolanaSignature(pk, sig, challenge, enc?)` + `buildOffchainPreimage()` | [`src/server/signature.ts`](../src/server/signature.ts) |
| Routes | thread `body.signEncoding` into the three wallet verifications | [`src/server/routes.ts`](../src/server/routes.ts) (`loginWallet` 346-380, `connectWallet` 386-440, `register` 277-286) |
| Handshake | local re-verify probe; emit `signEncoding`; HW key message + `keyMsgVersion` | [`src/client/authClient.ts`](../src/client/authClient.ts) (`walletHandshake` 258-271) |
| Key derivation | `master`/wrap path for HW accounts; `walletAppKeyMessageHw` | [`src/core/index.ts`](../src/core/index.ts), [`src/core/crypto.ts`](../src/core/crypto.ts) |
| User record | add `keyMsgVersion`, `hwAccount`, wrap-blob fields | `UserData` ([`src/core/types.ts`](../src/core/types.ts)) |
| UI | "Hardware wallet detected — back up your recovery code" enrollment step | [`src/ui/WalletMethod.tsx`](../src/ui/WalletMethod.tsx) |

All new fields are **optional** and default to today's behavior, so old clients and old records keep
working (additive, non-breaking on the read path).

---

## 6. Backward compatibility & migration

- **Software wallets:** unaffected. No `signEncoding` → server uses `raw`; `keyMsgVersion` defaults to
  `v1-nl`; key derivation path is byte-identical.
- **Existing accounts:** no migration. `hwAccount`/wrap-blob fields are absent → treated as software.
- **An existing wallet that was a Ledger and somehow registered before this PRD:** none can exist —
  they all `401`ed and never created a record. So there is no "legacy Ledger account" class to migrate.
- **Versioned-string discipline** (`CRYPTO_SPEC.md` §7): `walletAppKeyMessageHw`, `"ttc-hw-wrap-v1"`, and
  `keyMsgVersion` are new domain separators; changing them later is a clean break for HW accounts only and
  must be added to the §7 table.

---

## 7. Security considerations

- **No widening of auth.** The verifier still requires a signature whose pre-image embeds the single-use
  challenge. The encoding hint only selects which pre-image to reconstruct; it is not trusted.
  (Update `CRYPTO_SPEC.md` §5.1 to describe envelope verification.)
- **Bounded reconstruction.** The hintless fallback set is a compile-time constant (≤4 candidates, all
  format-0) → constant-time-ish, no client-driven amplification.
- **App-domain/ signer fields.** v0 embeds the signer pubkey and a 32-byte app domain; the server uses the
  *request's* `publicKey` and a fixed/echoed `appDomain`, so a mismatched signer can't be smuggled in.
- **Recovery factor is client-held.** Consistent with `CRYPTO_SPEC.md` §8 (no server custody). Losing both
  the Ledger *and* the recovery code = unrecoverable, by design.
- **Blind-sign avoidance.** Format-0 HW key message keeps users off the "enable blind signing" footgun,
  which is itself a phishing-risk reduction.
- **Audit scope:** signature verification, the wrap/recovery KDF chain, and the drift-recovery re-wrap flow
  all need review (see §9).

---

## 8. Testing

- **Golden vectors (must-have).** Capture real signatures from a physical Ledger (Nano S / S+ / X) via
  Phantom **and** Solflare, for both the login message (format 0) and the HW key message (format 0). Freeze
  the exact signed bytes as fixtures; assert `buildOffchainPreimage()` reproduces them and
  `verifySolanaSignature` accepts them. **No Ledger code ships without a passing golden vector.**
- **Unit:** raw-path unchanged; each envelope version round-trips; wrong hint / tampered envelope / wrong
  signer all reject; hintless fallback accepts a known envelope and rejects garbage.
- **Key safety:** simulate envelope drift (sign with v1 at register, v0 at login) → `wrapSig` unwrap fails
  → `wrapRec` recovers `master` → re-wrap succeeds → wallets decrypt. Assert **no path** loses `master`.
- **Regression:** full existing Jest suite stays green; software-wallet register/login/connect byte-stable.
- **Manual device matrix:** Nano S / S+ / X × Phantom / Solflare × {blind-sign on/off} → register, log
  out, log in, decrypt a wallet, simulate a firmware-version bump.

---

## 9. Rollout

1. **Phase 1 — auth only (unblocks the `401`).** Ship §3 (envelope-aware verification + client probe) with
   golden vectors. Ledger users can log in. **Gate Part 2 behind a flag**; until §4 lands, HW accounts are
   created with the *recovery factor mandatory* (no key-from-signature-only accounts ever exist).
2. **Phase 2 — key safety (§4).** HW key message, master-key wrap, recovery enrollment, drift-recovery.
3. **Audit** the combined surface (§7) before enabling HW registration in production consumers
   (Shyft, ttc.box).
4. **Docs:** update `CRYPTO_SPEC.md` §2.2/§5.1/§7 and `THREAT_MODEL.md`; add an integrator note to
   `README.md` ("hardware wallets supported; users must back up a recovery code").

---

## 10. Open questions

1. **Empirical envelope.** Which version does current Phantom-over-Ledger actually emit (v1 vs v0 vs
   legacy), and is the app domain 32 zero bytes? → resolved by capturing golden vectors (§8) **before**
   finalizing §3.2.
2. **Recovery factor default.** Biometric-unlock (reuse §4 infra, device-bound) vs a downloadable recovery
   code (portable, user-managed)? Recommend **offering both**, requiring **at least one** at HW
   registration.
3. **Wrap-blob storage.** Server-side on `UserData` (syncs across devices, matches `wallets[]`) vs
   client-only (less server trust)? Recommend **server-side** for cross-device parity, since it's
   non-secret ciphertext like the wallet bundle.
4. **Solflare / Backpack parity.** Do their Ledger paths emit the same envelope as Phantom? The hintless
   fallback set (§3.2) should cover divergence, but each needs a golden vector.
5. **Determinism confidence.** If real-world testing shows the envelope is in fact stable across the
   firmware versions we support, can Part 2's recovery factor be downgraded from *mandatory* to
   *recommended*? Decide after the device matrix (§8) — **default to mandatory** until proven otherwise.

---

> Companion read: `docs/CRYPTO_SPEC.md` (§2.2 Web3 app-key derivation, §5.1 challenge–response, §7 versioned
> strings) and `docs/THREAT_MODEL.md`. If this PRD and the code ever disagree once implemented, the code is
> correct and this document is the bug.
