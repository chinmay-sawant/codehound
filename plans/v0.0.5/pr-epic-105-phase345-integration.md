# chore: integrate epic #105 Phase 3–5 (single integration)

## Summary

Single integration for remaining epic #105 work: Phase 3 catalog residuals (C1–C4), Phase 4 product trust (canary corpus, rules explainability, recommended-pack pilot), and Phase 5 gated-tracker documentation. Applies shared maturity (including CWE-76 demotion from Structural) and closes the epic.

---

## Motivation / context

- Plan: `plans/v0.0.5/parallel-catalog-program.md` Phase 3–5
- Parent epic: #105
- Base SHA: `7d912d5be8528f80df0122259d24130c6f394df9`
- **One integration only** — no separate Phase 3 / Phase 4 / Phase 5 integration branches
- Child PRs are superseded by this PR

---

## Child streams

| Issue | Stream | Branch | Standalone PR |
|------:|--------|--------|---------------|
| #112 | C1 injection residual | `chore/cwe-trust-injection-residual` | #130 |
| #113 | C2 configuration residual | `chore/cwe-trust-configuration-residual` | #129 |
| #114 | C3 concurrency residual | `chore/cwe-trust-concurrency-residual` | #133 |
| #115 | C4 input-validation residual | `chore/cwe-trust-input-validation-residual` | #131 |
| #116 | Phase 3 integration (superseded) | — | closed via this PR |
| #117 | 4.1 canary corpus | `chore/canary-corpus-expansion` | #128 |
| #118 | 4.2 rules explainability | `feat/rules-explainability` | #134 |
| #119 | 4.3 recommended-pack pilot | `chore/recommended-pack-trust` | #132 |
| #120 | 5.1 gated trackers | `docs/phase5-gated-trackers` | #127 |
| #121 | 5.2 gated trackers | (same) | #127 |
| #105 | epic | this PR | closes epic |

---

## Changes

### Catalog (Phase 3)

- CWE-93 keep **Structural** (header CRLF; call_facts)
- CWE-15 keep **Heuristic**; FO for 472/1051/1067
- FO for concurrency 366/368/421/820/821 (367 deferred Heuristic)
- FO for 76/140/1173/1236; **remove CWE-76 from Structural allow-list**

### Product trust (Phase 4)

- Expanded canary corpus + runner script
- `codehound rules` explain surface + CLI/snapshot tests
- Recommended-pack pilot + stop-the-line policy docs

### Phase 5

- `phase5-gated-work.md` — **tracking complete** for epic #105; G1–G6 **implementations remain deferred** (banner updated; not product work)

### Shared

- `maturity.rs` Phase 3 FO list + CWE-76 demotion
- Audit §2.15 + program ledger Phase 3–5 complete

---

## Impact

| Area | Impact |
|------|--------|
| **Pack membership** | Newly FO rules leave recommended/security; CWE-76 no longer Structural/default-pack |
| **CLI** | New/extended rules explanation output |
| **Detectors** | Oracle-preserving rewrites only |

---

## Test plan

- [x] Merge all child streams without conflicts
- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4 passed)
- [x] `cargo test --locked --test cli_rules_explain` (7 passed)
- [x] `make test` (**458** nextest + 1 doctest passed)
- [x] `git diff --check`

---

## Related issues

- Closes #112
- Closes #113
- Closes #114
- Closes #115
- Closes #116
- Closes #117
- Closes #118
- Closes #119
- Closes #120
- Closes #121
- Closes #105

---

## PR metadata checklist

- [x] Self-assigned
- [x] Labels documentation + enhancement
- [x] Body under `plans/v0.0.5/pr-epic-105-phase345-integration.md`

---

## Follow-ups

- Deferred residual siblings (injection resource 619/917, secrets_in_config, toctou reopen only with new evidence)
- Phase 5 implementations only after reopen criteria in `phase5-gated-work.md`
