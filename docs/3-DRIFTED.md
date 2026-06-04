You're right — this is a real regression I introduced. Let me walk through exactly what's happening.

Where the encryption key lives
Look at src/client/session.ts:

setSession(...) writes the appKey (the AES key that decrypts every wallet) to sessionStorage["ttc_ek"] and caches it in a module-scope variable memoryAppKey.
getAppKey() reads from memory first, falling back to sessionStorage.
sessionStorage persists across reloads of the same tab and clears only when the tab is closed (or you call clearSession()).
So once a user signs in, the AES key sits in sessionStorage for the life of the tab. Anything running JS on that origin — including the SDK's own hooks — can read it.

What the new SDK hooks do with that key
Every signer/exporter I added in this refactor reads appKey straight from session:

useSigner() (src/react/useSigner.ts) → getAppKey() from sessionStorage. No prompt.
useSolanaSigner(wallet) and useEvmSigner(wallet) → wrap useSigner().sign(...) → which calls withDecryptedKey(wallet, appKey, fn). Silent — they just decrypt, sign, drop.
useExportKey(wallet) → same envelope, but the callback returns the plaintext secret instead of consuming it. <ExportKeyPanel> calls it on button click.
This is the SDK's documented design. From PRD_PRIVY.md §2.7:

the app key (ttc_ek) lives in sessionStorage + memory only, never localStorage, never the wire — so closing the tab forces re-auth before keys can be decrypted (session_expired).

And §2.6 explicitly flags the consequence:

The SDK's useSigner().sign(...) will succeed silently if the app key is hot in sessionStorage. For the reveal flow specifically, consider calling logout() + force re-auth first if you want the same friction.

The SDK cannot force a re-auth on its own. That's an app-level gate.

How the original demo handled it
The pre-refactor DemoShell deliberately did not trust sessionStorage for reveal/sign:

After login, it threw away the in-component knowledge of appKey and required the user to re-derive it.
The unlock() function (still present, DemoShell.tsx around line 165) calls deriveAppKeyFromPasskey / deriveAppKeyFromSignature / derivePasskeySecret again, validates by trying a decrypt, and stores the result in a separate local unlockedKey state.
Both Show/Hide and the original SignMessageCard were gated on that local unlockedKey, not on the session's appKey.
The session key is still there the whole time — the demo just chose to ignore it for sensitive actions. That's the "Re-auth to reveal" principle on the home page.

What I broke in the refactor
Two specific changes in DemoShell.tsx:

The SignMessageCard rewrite. The new card uses useSolanaSigner(wallet) / useEvmSigner(wallet). Those hooks decrypt via the session appKey. I dropped the unlockedKey gate and rationalized it as "matches real-wallet UX — you don't re-auth every tx". That's a defensible policy, but the home page principle #5 still says signing requires re-auth, and the new card silently signs the moment you press the button.

The ExportKeyShowcase card I added (titled "Or: drop-in <ExportKeyPanel />"). It renders right under the WalletsPanel and uses <ExportKeyPanel> to reveal the same Solana funds key that the WalletsPanel guards behind the ceremony. One click and the plaintext is in the DOM — no ceremony, no prompt. The demo now teaches the lesson and contradicts it on the next card down.

One change in /ui/page.tsx: I added an <ExportKeyPanel wallet={active.encrypted}> directly under the <LoginPanel>. Same issue — fresh login, immediate reveal.

Bridge page: signs silently via useSolanaSigner for embedded wallets. Same root cause (session appKey), no extra leak beyond what's already in DemoShell.

So when you tested
You signed in (any method). appKey landed in sessionStorage["ttc_ek"].
The WalletsPanel still blocked Show/Hide behind the manual ceremony — that part works.
You clicked "Reveal private key" on the ExportKeyPanel card below → the SDK called withDecryptedKey(funds, sessionStorage.ttc_ek, fn) → plaintext landed in React state → rendered in the monospace block.
You pressed "Sign message" → same thing, decrypt → sign → drop. No prompt.
Both behaviors are correct for the SDK, but they violate the demo's stated principle. The ceremony in the WalletsPanel was load-bearing; I added paths around it.

Two ways to reconcile
I'm not editing — just laying out the options for you:

Restore the ceremony for the new components. Gate <ExportKeyPanel> and the SignMessageCard behind unlockedKey (same as Show/Hide). To make <ExportKeyPanel> honor an app gate cleanly, the SDK could expose a unlocked prop on the panel, or the demo could just conditionally render it after the ceremony unlocks. Also: call auth.logout() before navigating to a reveal flow, as PRD §2.6 suggests — that forces a fresh login.

Update the principle to match SDK behavior. Drop "Re-auth to reveal" as a hard claim and reframe it as "tab close = re-auth required" (which is genuinely the SDK's model — session_expired state is the gate). The signing-silently part is then consistent with real-wallet UX; the reveal-silently part is the documented trade-off vs Privy's hosted iframe.

The first preserves the demo's narrative but adds friction. The second is honest about what the SDK provides. I'd lean toward option 1 for the ExportKeyPanel (the demo's whole point is the security ceremony) and option 2 for signing (gating every signature on re-auth would be unusual UX in any real app), but tell me which way you want to go.