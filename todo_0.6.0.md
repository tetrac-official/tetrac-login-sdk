Still open — your call
ID	Sev	Status
H-3	High	No strength floor on a typed passkey. 7a937e5 made the generator the default, which is the practical mitigation, but disabled={busy || !email || !passkey} still accepts any non-empty string. A real floor is a breaking change for existing weak-passkey accounts.
H-5(2)	High	Wallet-address squatting — registering with a victim's real Solana address as the identity publicKey, with no proof of possession. Distinct from the email squatting you dismissed.
M-4	Med	KV email-index registration is check-then-act. SQL is structurally safe (PRIMARY KEY (email, app_id)); the KV path needs an hsetnx-style primitive.
M-8	Med	Vault reachable via Symbol.for("tetrac.vault"); slot is configurable: true. Mitigates to "XSS is already fatal" — arguably accepted.
M-9	Med	Biometric-unlock blob isn't bound to an account/appId; unlockViaBiometric arms whatever the blob yields.
C-1 and every other High/Medium had already landed. M-13 (empty README/SECURITY/CHANGELOG) closed with the SECURITY.md I wrote at the start of this turn.

Want me to take H-5(2) and M-4? Those two are contained. H-3, M-8, and M-9 each involve a product decision I shouldn't make for you.