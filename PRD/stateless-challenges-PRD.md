# PRD — Stateless (HMAC) login challenges

| | |
|---|---|
| **Status** | Draft — recommendation in §9, decisions needed in §8 |
| **Date** | 2026-08-05 |
| **Target** | v1.0 (breaking changes permitted; no migration or deprecation shims) |
| **Scope** | `src/server/challenge.ts`, `src/storage/store.ts`, `src/storage/sql/*`, `src/core/config.ts` |
| **Closes** | audit.md M-1 (residual half) — targeted account lockout via the `/challenge` bucket |

---

## 1. Summary

Login challenges are currently **minted and stored**. This proposes minting them as a
**signed token the server can re-verify without having stored it**, so that issuing a
challenge writes nothing and therefore needs no rate limit — which is what removes the
remaining half of the targeted-lockout attack.

```
challenge = b64url( nonce ‖ issuedAt ‖ HMAC-SHA256(secret, appId ‖ publicKey ‖ nonce ‖ issuedAt) )
```

## 2. Why this is on the table

The first half of M-1 is fixed: challenges now accumulate per identity rather than
overwriting, so an attacker can no longer destroy a challenge a victim is mid-way through
signing.

The second half is not. `/challenge` is rate-limited on the **named target**, and the
endpoint is unauthenticated, so anyone can spend a victim's budget:

```
10 anonymous /challenge for the victim's email  →  victim's /challenge: 429
```

At 10/min one unauthenticated client holds a named account out of its own login
indefinitely. Keying that bucket on the *requester* instead would fix it, but `/challenge`
runs **before** authentication by definition — there is no requester identity in-band. The
only out-of-band identifier is the client IP, which the SDK cannot obtain safely on its own
(it sees a `Request`, with no socket, and headers are attacker-controlled without a trusted
proxy that overwrites them).

Stateless challenges sidestep the question: if issuance costs nothing, there is no budget to
drain and no bucket to key.

## 3. Design

**Issue** (`/challenge`) — no write at all:

1. `nonce = randomHex(16)`, `issuedAt = Date.now()`.
2. `mac = HMAC-SHA256(config.challengeSecret, appId ‖ publicKey ‖ nonce ‖ issuedAt)`.
3. Return `b64url(nonce ‖ issuedAt ‖ mac)`.

**Consume** (`consumeChallenge`):

1. Decode; reject on malformed input, unchanged in spirit from today's `^[0-9a-f]{64}$` guard.
2. Recompute the MAC over the SAME `(appId, publicKey)` the route is authenticating and
   compare in constant time. A challenge issued for one account is not valid for another.
3. Reject if `now - issuedAt > challengeTtlSeconds`, or if `issuedAt` is in the future
   beyond a small skew allowance.
4. **Atomically claim the nonce.** First claimant wins; every later one fails. This is the
   single-use property and it is the only state involved.

The claim needs a new port method, and the KV side already has the primitive:

```ts
/** Atomically claim a one-time nonce. true = first claim; false = already used. */
claimNonce(appId: string, nonce: string, ttlSeconds: number): Promise<boolean>;
```

`KvAuthStore` implements it with `incr` — which is atomic and, per StorageAdapter invariant
2, returns `1` on an expired key — then stamps the TTL, exactly as `hitRateLimit` does.
`SqlAuthStore` implements it as an `INSERT … ON CONFLICT DO NOTHING` and reports whether a
row appeared.

## 4. Why the stored design exists

**There is no recorded decision.** `src/server/challenge.ts` has carried the same shape
since `165422c "Version 0.1 release bundled with nextjs demo"`; no ADR, no PRD, no comment
argues against a stateless variant. So this is not a considered trade-off being revisited —
it is the obvious first implementation, never challenged.

That said, the stored design is not naive, and three things genuinely favour it:

**It needs no server secret.** The SDK currently holds **zero** server-side secrets. Grep
`src/core/config.ts` for one and there is nothing — the only credentials anywhere are the
integrator's own database connection strings in `resolve.ts`. Every security property today
rests on client-held key material and on a store the integrator already had to provision.
Introducing a signing key the deployment must generate, keep stable, distribute to every
instance, and rotate is an architectural first, and it is the kind of thing integrators get
wrong (committed to git, regenerated per deploy, different per replica).

**Single-use is trivially, visibly correct.** `GETDEL` on one key is atomic and obviously
right. Anyone reading it can see the replay defence. HMAC + timestamp + claim-set is three
mechanisms that must each be correct, and the failure mode of getting the claim step wrong
is silent challenge replay.

**A store is mandatory anyway.** "Stateless" is not a deployment simplification here — the
SDK already requires an `AuthStore`, so removing a write does not remove a dependency.

## 5. Pros

- **Closes the M-1 residual without needing requester identity.** Issuance writes nothing,
  so there is no per-target budget to exhaust and no reason to rate-limit it.
- **No unauthenticated write path at all.** Today an anonymous flood creates one storage
  entry per request (bounded by TTL and the rate limit, but real). Afterwards, state is
  created only on *successful* consumption, which requires a valid signature — the attacker
  cannot inflate it.
- **Secret compromise is low-impact**, which is counterintuitive and worth stating. A
  challenge is a public value that anyone can already obtain from the endpoint, so an
  attacker who can forge one gains nothing: they still need the account's signature over it.
  The MAC exists to stop *attacker-chosen* values entering the claim-set, not to keep the
  challenge confidential.
- **Removes an enumeration signal.** Issuance no longer needs the account to exist, so
  `/challenge` can return a well-formed challenge for an unknown email instead of a
  distinguishable 400 — closing the oracle in audit.md L-3.
- **Cheaper.** One HMAC instead of a storage round-trip on the hottest pre-auth endpoint.

## 6. Cons

- **A mandatory server secret.** New required config, same shape as `origin`: must be
  present, ≥32 bytes, stable forever, identical across every instance. Missing or drifting
  between replicas means challenges issued by one instance fail on another.
- **Rotation invalidates outstanding challenges.** A 300s blip unless the verifier accepts
  a previous secret during an overlap window — which means the config takes a *list*, not a
  string, and that is more surface to get wrong.
- **It does not eliminate storage; it moves it.** The claim-set is still a write per
  consumed challenge. The win is *where*: from unauthenticated issuance to authenticated
  consumption. Worth being precise about, because "stateless" oversells it.
- **`/challenge` still reads.** For email accounts the route resolves the email to a public
  key and reads the record for `pbkdf2Iterations`. Those reads remain, so the endpoint is
  not free and is still worth a generous limit for load reasons.
- **Three mechanisms instead of one.** MAC verification, clock/TTL validation, and the
  atomic claim each have to be right. The middle one introduces clock skew as a new
  correctness input across instances.
- **Longer challenge string.** ~112 hex chars vs 64. It is embedded in the Ledger off-chain
  message, which caps at 1212 bytes — comfortable, but no longer a rounding error.

## 7. Effort

Comparable to the lost-update refactor already landed: the `AuthStore` port changes
(`putChallenge`/`takeChallenge` replaced by `claimNonce`), both backends, the SQL schema
(`ttc_challenges` becomes a nonce claim-set), the conformance suite's challenge section, and
a new required config value threaded through `resolveConfig`. Call it a day of work with
tests, plus a real-engine run once Docker is available.

## 8. Open questions

**8.1 — Is a mandatory server secret acceptable?** This is the decision the rest hangs on.
It is the SDK's first, and it changes the deployment story from "point it at a database" to
"point it at a database and generate a key". If the answer is no, the alternative for M-1 is
to accept the residual and document it, or to revisit requester identity.

**8.2 — Rotation.** Single secret with a 300s blip, or a list with an overlap window?

**8.3 — Should `/challenge` stop revealing account existence** at the same time (return a
well-formed challenge for unknown identities)? It becomes nearly free here, and it closes
L-3 — but it changes the client's error path, since `loginWithEmail` currently learns
"unknown account" from the 400.

**8.4 — Keep a rate limit on `/challenge` anyway?** Issuance no longer needs one for abuse,
but the endpoint still does two storage reads for email accounts. A generous per-target
limit for load — sized so it is not a lockout — may still be worth keeping.

## 9. Recommendation

**Worth doing, but not next.** It is the correct end state: it removes the last
unauthenticated write, closes M-1 without inventing requester identity, and makes L-3
closeable for free.

But it is the only proposal so far that adds a *mandatory secret*, and that is a real
increase in how wrong an integrator can go — a secret regenerated on each deploy silently
breaks every in-flight login, and one committed to a repo looks like a compromise even
though §5 argues it barely is. The remaining M-1 residual is a targeted throttle on
`/challenge`, not the wallet-key destruction and unbounded-record classes already fixed.

Suggested order: land the cheap items still open (L-1, L-2, L-4, Ledger envelope pinning),
answer §8.1, and take this as a deliberate piece of work rather than folding it into the
audit remediation.
