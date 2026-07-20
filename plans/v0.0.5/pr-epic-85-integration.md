# chore: integrate epic #85 CWE file-permissions trust workstreams

## Summary

- Merge the four Phase 1–4 branches for the CWE-276/277/278/279/281/921 catalog-trust tranche into one integration branch.
- Combined validation green: `make lint`, focused CWE/maturity tests, `make test` (**443 passed**).
- Prefer merging **this** PR into `master` instead of the four child PRs separately.

## Motivation / context

Plan: `plans/v0.0.5/cwe-file-permissions-trust.md`  
Parent audit: `plans/v0.0.5/cwe-catalog-trust-audit.md` §2.12  
Epic: #85

| Child issue | Branch | Standalone PR |
|------------:|--------|---------------|
| #86 | `docs/cwe-file-perm-phase1-evidence` | #92 |
| #87 | `fix/cwe-file-perm-phase2-detectors` | #90 |
| #88 | `chore/cwe-file-perm-phase3-canary` | #93 |
| #89 | `docs/cwe-file-perm-phase4-closure` | #91 |

## Changes

### Integrated outcomes

| Area | Outcome |
|------|---------|
| Phase 1 evidence | Per-rule sink/signal/SI/span table + fixture multiset baseline |
| Phase 2 detectors | Call-facts span hygiene; NEEDLES labels; maturity quarantine |
| Phase 3 canary | 0 findings / 126 files (gopdfsuit + monsoon + go-retry) |
| Phase 4 docs | Audit §2.12 + plan/pointers closed on integrated tree |

### Final dispositions

| Rule | Maturity |
|------|----------|
| CWE-276 | fixture-only |
| CWE-277 | **Heuristic** (keep) |
| CWE-278 | fixture-only |
| CWE-279 | fixture-only |
| CWE-281 | fixture-only |
| CWE-921 | fixture-only |

No Structural promotions. Zero-hit canary does not delete or promote.

### Integration method

```text
origin/master
  + docs/cwe-file-perm-phase1-evidence
  + docs/cwe-file-perm-phase4-closure
  + chore/cwe-file-perm-phase3-canary
  + fix/cwe-file-perm-phase2-detectors
```

Plan-file add/add conflicts resolved; maturity code from Phase 2 is authoritative.

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | Five CWEs quarantined from recommended/security packs; CWE-277 remains Heuristic under default maturity |
| **API / CLI** | Unchanged IDs/messages; pack eligibility via maturity |
| **Performance** | Neutral |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| CWE-276/278/279/281/921 | Still under `--profile all` / `--only`; not default pack members |

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4)
- [x] `cargo test --locked --lib rules::maturity` (3)
- [x] `make test` — **443 passed**
- [x] Phase 3 canary table in plan/audit (0/126)

### Commands

```sh
git checkout chore/epic-85-integration
make lint
make test
```

## Related issues

- Closes #86
- Closes #87
- Closes #88
- Closes #89
- Closes #85

## Integration note for child PRs

Standalone PRs #90–#93 are **superseded** by this integration PR. Merge this one; close the others without merging if GitHub does not auto-close them.

## PR metadata checklist (author)

- [x] Self-assigned
- [x] Labels: `enhancement`, `documentation`, `bug`
- [x] Related issues filled
- [x] Body at `plans/v0.0.5/pr-epic-85-integration.md`

## Follow-ups

- Revisit CWE-277 only with real-module hits or broader mode taxonomy (§1.3)
- Residual CWE long-tail inventory outside this six-rule set
