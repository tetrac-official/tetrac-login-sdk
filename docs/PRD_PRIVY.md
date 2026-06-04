# PRD — Privy vs `@tetrac/login-sdk`: capability mapping & component design

A side-by-side of **what Privy does inside a codebase** and **how `@tetrac/login-sdk` does (or
should do) the same thing**. Privy is a Wallet-as-a-Service (custodial MPC); tetrac is the
self-custody equivalent and can replace it. This document is not a drop-in compat plan — it is a
design review: for each capability Privy provides, we state Privy's pattern, tetrac's current
pattern, and the recommended component/codebase shape.

- **Status:** Draft v1
- **Author:** TTC Engineering
- **Date:** 2026-06-03
- **Reference app:** `/Users/mac/Documents/Shyft.lol` (live Privy 3.x consumer)
- **Companion docs:** `docs/PRD.md` (base SDK), `docs/USE_IN_CODE.md` (integration), `.claude/skills/replace-privy/SKILL.md` (migration mechanics)
- **Out of scope:** social/OAuth logins (Google/Twitter/GitHub) — tetrac has no equivalent and these are intentionally excluded here.

---

## 1. The foundational difference (read first)

Privy and tetrac solve the same surface problem — *let a user log in and end up holding a usable
Solana/EVM wallet* — with **opposite trust models**. Every design decision below flows from this.

| Concern | Privy (WaaS) | `@tetrac/login-sdk` (self-custody) |
|---|---|---|
| Where keys are made | Privy's server-side MPC | The browser (`Keypair.generate()`, viem `generatePrivateKey()`) — `src/client/wallet.ts` |
| Who can decrypt | Privy (holds shares) | Only the user's browser (AES under an app key never sent to a server) |
| What the server stores | MPC shares + OAuth identities | Ciphertext blob + public key only — `UserData.wallets[]` |
| Encryption key origin | Privy infra | Derived client-side: `PBKDF2(passkey, email)` or `SHA256(walletSignature)` — `src/core/crypto.ts` |
| Recovery | Privy reconstructs from shares | Deterministic re-derivation from the same passkey+email / wallet signature |
| Backend | Privy's hosted API | Your routes + your storage — `src/server`, `src/next`, `src/storage` |
| UI | Hosted modal + reveal iframe | Headless — the app renders everything (today) |

**Design consequence:** Privy can centralize behavior because it owns the keys and the backend.
tetrac cannot — keys and trust live on the client — so tetrac's value is *clean client-side
primitives*. The open design question this PRD answers is **how much of Privy's convenience layer
(hooks that hand you wallets, a login modal, signer objects) tetrac should reproduce on top of
those primitives**, vs. leaving it to each app (as it does today, which forces every consumer to
re-write the same glue — see §2.4 and §2.5).

---

## 2. Capability-by-capability mapping

For each capability: **Privy** (how it appears in code) → **tetrac today** (what exists in `src/`)
→ **Recommended design**.

### 2.1 App bootstrap / provider

- **Privy:** one `<PrivyProvider appId config={...}>` at the root. `config` carries *everything* —
  login methods, appearance, embedded-wallet auto-create, supported chains, RPCs, external
  connectors. The provider also mounts the hosted login modal.
- **tetrac today:** `<AuthProvider apiBaseUrl walletGen config={{webauthn}}>` (`src/react/AuthProvider.tsx`).
  It constructs an `AuthClient`, hydrates session status from storage, and exposes
  `{ client, status, publicKey, email, refresh }`. No UI, no RPC, no external-wallet wiring.
- **Recommended design:** keep one provider, but **widen what it owns** so apps stop re-implementing
  glue (see 2.4). The provider — not each app — should hold the loaded `UserData`/wallets, the
  active-wallet selection, and (optionally) the Solana connection. RPC + external-wallet adapters
  stay the app's job via `@solana/wallet-adapter-react` (tetrac shouldn't absorb Solana RPC
  config the way Privy does — that's a WaaS lock-in we don't want).

### 2.2 Login UI

- **Privy:** `usePrivy().login()` opens a fully-built, themeable hosted modal. This is the single
  biggest "free" thing Privy gives. `config.appearance` controls branding.
- **tetrac today:** nothing. The app builds the modal and calls `registerWithEmail` /
  `loginWithEmail` / `connectWallet` / `registerWithBiometric` itself (`useAuth`, `src/react/useAuth.ts`).
- **Recommended design:** **stay headless by default, but ship an optional UI package**
  (`@tetrac/login-sdk/ui`, tree-shakeable, not pulled in unless imported). A themeable
  `<LoginPanel methods={["email","wallet","biometric"]} onSuccess />` closes the largest adoption
  gap without forcing a UI on apps that want their own. Do **not** route `login()` through a
  global `window` event the way the migration skill sketches — that pattern is a workaround for the
  missing component, not a design we want to bless.

### 2.3 Login methods & wallet creation

- **Privy:** `config.loginMethods` + `embeddedWallets.{chain}.createOnLogin: "users-without-wallets"`.
  A wallet is conjured server-side after login.
- **tetrac today:** the method **is** the wallet creation — `AuthClient.registerWithEmail` /
  `registerWithBiometric` / `connectWallet` each call `generateWalletBundle()` client-side and
  POST only ciphertext (`src/client/authClient.ts`). Roles (`funds`, `signing`) are first-class —
  Privy has no equivalent of multi-role wallets.
- **Recommended design:** this is tetrac's strongest area — **keep it, and surface the role model
  as a feature** (Privy can't do agent/signing wallets). Document `walletGen` as the analog of
  `embeddedWallets.createOnLogin`. No structural change needed.

### 2.4 Accessing the active wallet & public key  ← **biggest design gap**

- **Privy:** `useWallets()` (root + `/solana`) returns the wallet list directly; `usePrivy().user`
  carries `linkedAccounts`. Everything you need to render "you are 0xABC…" is in a hook, already
  loaded.
- **tetrac today:** **closed.** `AuthProvider` now owns the `/user-data` fetch+cache, auto-refetches
  on auth status change, and exposes the user record through context. Shipped hooks:
  - `useUser()` → `{ user: UserData | null, loading, refetch }` (`src/react/useUser.ts`)
  - `useWallets()` → `WalletEntry[]` — `{ chain, role, address, isEmbedded, encrypted }`. Embedded
    entries carry the `EncryptedWallet` blob; external entries set `encrypted: null` so the
    consumer routes signing through their wallet adapter. (`src/react/useWallets.ts`)
  - `useActiveWallet({ chain? = "solana" })` → `WalletEntry | null`. Applies the
    "external connected wins, else embedded funds" rule inside the SDK. (`src/react/useActiveWallet.ts`)
- **External wallet integration:** the SDK does not import `@solana/wallet-adapter-react` (that
  would re-create Privy-style RPC/adapter centralization — see §2.1). Instead, `<AuthProvider>`
  takes an `externalSolanaAddress?: string | null` prop; the app pipes Phantom/Backpack's
  connected address in via a thin bridge component. `useActiveWallet()` then applies the
  external-wins rule using that prop.

  Net effect: the ~180-line Shyft `usePrivyWallet.ts` shim (user-data fetch, active selection,
  signer envelope) collapses into `useActiveWallet()` + `useSolanaSigner()` calls in app code.

### 2.5 Signing transactions & messages

- **Privy:** the wallet object from `useWallets()/solana` exposes
  `signTransaction({ transaction: bytes }) → { signedTransaction: bytes }` (and a variadic batch
  form). The app never touches the key.
- **tetrac today:** `useSigner()` (`src/react/useSigner.ts`) exposes low-level primitives —
  `decrypt`, `solanaKeypair`, `sign(blob, fn)` — built on `withDecryptedKey` (`src/client/wallet.ts`),
  which decrypts only for the callback's lifetime then drops the reference. Correct and secure, but
  **the app must assemble the actual `signTransaction(tx)` itself** (deserialize → `partialSign` →
  reserialize), as the Shyft shim does. (The hook was previously named `useWallet()`; renamed to
  free `useWallets()` for the wallet-list hook in §2.4.)
- **Recommended design:** keep the low-level `withDecryptedKey`/`sign` primitives (they're the
  security-critical core), and layer **ready-made high-level signers on top** so apps don't rebuild
  the envelope. **Shipped:**
  - `useSolanaSigner(wallet)` → `{ publicKey, signTransaction, signAllTransactions, signMessage }`
    in `@solana/wallet-adapter-react` / Anchor `Wallet` shape — drops straight into
    `AnchorProvider`. Each signing call routes through `withDecryptedKey` and zeroes the secret
    bytes on completion. (`src/react/useSolanaSigner.ts`)
  - `useEvmSigner(wallet)` → a viem `LocalAccount` (via `toAccount`) whose `signMessage` /
    `signTransaction` / `signTypedData` each go through `withDecryptedKey`. Plugs into
    `createWalletClient({ account })`, wagmi custom connectors, etc. (`src/react/useEvmSigner.ts`)

  Naming is collision-free: `useSigner()` returns low-level primitives,
  `useSolanaSigner()` / `useEvmSigner()` return ready-made chain-specific signers, and
  `useWallet(s)` is reserved for the wallet-access hooks in §2.4. Both new hooks take an explicit
  `EncryptedWallet` argument today; once §2.4 lands they can default to `useActiveWallet()`.

### 2.6 Exporting / revealing a private key

- **Privy:** `useExportWallet().exportWallet({ address })` pops Privy's **hosted reveal iframe** —
  the app never sees plaintext (XSS-isolated by the sandbox). This is the working flow in
  `Shyft.lol/src/app/export-key/page.tsx` today.
- **tetrac today:** no export hook; the app calls `useSigner().sign(blob, secret => secret)` to
  get the plaintext and renders it itself (the pattern documented in the migration skill).
- **Recommended design:** ship a first-class `useExportKey()` →
  `{ reveal(): Promise<string>, clear() }` that wraps `withDecryptedKey`, plus an **optional**
  `<ExportKeyPanel>` (in `@tetrac/login-sdk/ui`) that handles the reveal/copy/auto-clear/timeout UX
  and the React-Native-WebView `postMessage` contract Shyft's export page relies on. Self-custody
  means *the app's DOM holds the plaintext* — so the SDK should own the safe-reveal UX rather than
  leave each app to get the clipboard-timeout and CSP story right. Document the trade-off
  explicitly: no iframe sandbox, so the reveal route is XSS-sensitive.

### 2.7 Sessions, persistence & status

- **Privy:** opaque; Privy manages the session and exposes `ready` (async) + `authenticated`.
- **tetrac today:** explicit and well-designed (`src/client/session.ts`). Three-state model:
  `authenticated` / `session_expired` / `unauthenticated`. Critically, the **app key
  (`ttc_ek`) lives in `sessionStorage` + memory only, never `localStorage`, never the wire** — so
  closing the tab forces re-auth before keys can be decrypted (`session_expired`). This is a
  stronger, more legible model than Privy's opaque `ready`.
- **Recommended design:** keep as-is; **document `session_expired` as a feature** (Privy has no
  comparable "logged in but can't spend until re-auth" state). One ergonomic add: expose a derived
  `ready` boolean from the provider for teams porting Privy code that gates UI on it.

### 2.8 Backend / where the work runs

- **Privy:** calls Privy's hosted API. Nothing to run.
- **tetrac today:** you run it. `createNextAuthRoutes({ storage })` mounts one catch-all at
  `app/api/auth/[...action]/route.ts` (`src/next/routes.ts`) over framework-agnostic handlers
  (`src/server/routes.ts`): `challenge`, `register`, `login`, `login-wallet`, `connect-wallet`,
  `import-wallet`, `user-data`, `search-wallet`. Storage is pluggable — Redis / Upstash / Vercel KV
  (`src/storage`). Replay-safe challenges, dual-key (IP + identifier) rate limiting, and Solana
  signature verification are all built in.
- **Recommended design:** keep. This is the deliberate cost of self-custody (no vendor backend) and
  it's already clean. Two doc-level additions: a one-command local bootstrap, and make the
  client/server header + key-prefix config (`src/core/config.ts`) prominent so multiple apps can
  share one storage namespace safely.

### 2.9 User / account model

- **Privy:** `user.linkedAccounts[]` — a heterogeneous list (wallets, emails, OAuth identities),
  probed by `walletClientType === "privy"`, `chainType`, etc.
- **tetrac today:** `UserData` (`src/core/types.ts`) — `{ publicKey, email?, authMethod, wallets[],
  createdAt }`, where each wallet is `{ chain, role, publicKey, encryptedSecret }`. Cleaner and
  typed; "embedded vs external" is `role`/`chain` + whether an external adapter is connected, not a
  `walletClientType` string.
- **Recommended design:** keep the typed model. When 2.4 lands, expose helper selectors
  (`user.embeddedFunds(chain)`, `user.find({chain, role})`) so apps stop writing
  `wallets.find(w => w.chain === "solana" && w.role === "funds")` by hand everywhere.

---

## 3. Where to follow Privy, and where not to

| Privy pattern | Adopt it? | Why |
|---|---|---|
| Hooks return wallets/pubkey already-loaded (`useWallets`, `user`) | **Yes** (§2.4) | Removes the #1 source of per-app glue; no trust-model conflict. |
| Ready-made transaction signers on the wallet object | **Yes** (§2.5) | Apps shouldn't rebuild the serialize/partialSign envelope. |
| A batteries-included login modal | **Yes, but optional** (§2.2) | Biggest adoption win; must stay tree-shakeable and overridable. |
| Provider owns the Solana RPC / connection config | **No** (§2.1) | That's WaaS centralization; keep RPC in the app's `ConnectionProvider`. |
| Opaque session + `ready` flag | **No** (§2.7) | tetrac's explicit 3-state model is better; only expose a derived `ready` for porting. |
| Server-side custody / hosted reveal iframe | **Cannot** (§2.6) | Antithetical to self-custody; replace with an SDK-owned safe-reveal UX instead. |
| `walletClientType` string probing | **No** (§2.9) | Typed `{chain, role}` selectors are cleaner. |

---

## 4. Recommended target component architecture

Concrete module shape that closes the gaps above. Additive — no breaking change to the core.

```
src/react/
  AuthProvider.tsx     // EXISTS: also fetches+caches UserData; accepts externalSolanaAddress prop
  useAuth.ts           // EXISTS: status + auth actions
  useUser.ts           // EXISTS: { user, loading, refetch } — reads the cached user-data fetch
  useWallets.ts        // EXISTS: list of {chain, role, address, isEmbedded, encrypted}
  useActiveWallet.ts   // EXISTS: the one wallet to sign/display with (external-wins rule lives here)
  useSolanaSigner.ts   // EXISTS: { publicKey, signTransaction, signAllTransactions, signMessage } (adapter-shaped)
  useEvmSigner.ts      // EXISTS: viem LocalAccount over withDecryptedKey
  useSigner.ts         // EXISTS (renamed from useWallet): low-level decrypt/sign/keypair primitives
  useExportKey.ts      // NEW: { reveal, clear } over withDecryptedKey

src/ui/                // NEW, optional entry: "@tetrac/login-sdk/ui" (tree-shakeable)
  LoginPanel.tsx       // email / wallet / biometric, themeable — the headless-gap filler
  ExportKeyPanel.tsx   // safe reveal: copy + auto-clear + RN-WebView postMessage
```

Net effect on a consuming app (measured against the Shyft migration): the hand-written
`usePrivyWallet.ts` shim (~180 lines: user-data fetch, active-wallet selection, signer envelope,
connection) collapses into `useActiveWallet()` + `useSolanaSigner()` imports, and the hand-built
login modal becomes `<LoginPanel>` (or stays custom if the app wants).

---

## 5. Decisions to confirm before building

1. **Ship a UI package?** (§2.2/§2.6) Recommended yes, as an optional `@tetrac/login-sdk/ui`
   entry. Confirms the project is willing to own login + reveal UX, not just primitives.
2. ~~**Rename `useWallet` → `useVault`/`useSigner`?**~~ **Done** (§2.5) — renamed to `useSigner` to
   free `useWallets()` for the wallet-list hook. Breaking change for current consumers (next-ttc);
   coordinate the bump when they upgrade.
3. ~~**Provider owns the user-data fetch?**~~ **Done** (§2.4) — `AuthProvider` fetches on auth
   change, exposes through `useUser()`/`useWallets()`/`useActiveWallet()`. Cache policy: refetch
   on `status === "authenticated"` and on manual `refetch()`; no window-focus refetch (apps that
   want it can `useEffect(() => refetch(), [windowFocus])`).
4. ~~**EVM signer parity?**~~ **Done** (§2.5) — `useEvmSigner()` ships a viem `LocalAccount` over
   `withDecryptedKey`, matching the Solana parity. Apps wire it into their own viem/wagmi clients.
5. **Keep RPC out of the provider?** (§2.1) Recommended yes — confirms we don't replicate Privy's
   RPC centralization.

---

## 6. Summary

tetrac already matches or beats Privy on the **hard, security-critical** parts — client-side key
generation, deterministic recovery, encrypted-at-rest wallets, an explicit session model, and a
self-hostable backend with rate limiting and replay-safe challenges. Where Privy is currently ahead
is **convenience packaging**: hooks that hand you loaded wallets, ready-made signers, and a hosted
login/reveal UI. Those are reproducible on top of tetrac's existing primitives *without*
compromising self-custody — and §4 is how. The one Privy capability tetrac deliberately won't
match is server-side custody (the hosted reveal iframe); for that, the right move is an SDK-owned
safe-reveal component, not a vendor sandbox.
