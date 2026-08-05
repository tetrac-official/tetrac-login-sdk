# Audits

Security audits of `@tetrac/login-sdk`.

| Date | Version | Report | Result |
|---|---|---|---|
| 2026-08-05 | v0.6.0 (`ae91299`) | [2026-08-05-security-audit-v0.6.0.md](2026-08-05-security-audit-v0.6.0.md) | 1 critical, 7 high, 14 medium |

## Files

- **`2026-08-05-security-audit-v0.6.0.md`** — the audit report. Threat model, findings with attack scenarios and fixes, remediation roadmap, coverage and known gaps.
- **`2026-08-05-raw-findings.json`** — raw machine output backing the report: all 112 discovery findings, the 19 completed adversarial verdicts, 137 recorded strengths, and per-dimension coverage notes. Kept so the unverified candidates in §6 of the report can be re-triaged rather than taken on trust.

## How to read the report

Every finding carries a provenance tag:

- **`[first-hand]`** — the code and its callers were read directly and the behaviour confirmed.
- **`[adversarial]`** — survived two independent verifier agents instructed to refute it.
- **`[candidate]`** — reported with quoted evidence but **not** independently verified. A lead, not a conclusion.

The 2026-08-05 verification pass is **incomplete** (207 of 240 agents aborted on an API session limit; ~8% of verdicts landed). All Critical and High findings are `[first-hand]` and/or `[adversarial]`; most Medium and all §6 entries are unverified. See §9 of the report for the full list of gaps.

Do not use the raw workflow summary line (`confirmed: 5, refuted: 107`) as a result — findings whose verifiers *errored* were tallied as refuted.

## Suggested next pass

1. Re-run adversarial verification over the §6 candidates.
2. Run the completeness critic (never executed): TOCTOU, Unicode/homoglyph email normalization, clock skew, fail-open `catch` blocks, cross-subsystem seams.
3. Build proof-of-concept regression tests for C-1 (signature relay) and H-1 (gate-mode secret recovery) alongside the existing `tests/audit-*.test.ts` suite.
