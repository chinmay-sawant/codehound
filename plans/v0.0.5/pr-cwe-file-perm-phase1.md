# docs(cwe): file-permissions Phase 1 evidence baseline

## Summary

- Freeze the Phase 1 evidence baseline for access-control file-permission CWE siblings
  `CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-281`, and `CWE-921`.
- Commit the tranche plan and a dated evidence record (per-rule sink/signal/SI/negatives/span,
  pack membership, fixture oracle, six-rule multiset, disposition candidates).
- Docs/analysis only — **no** detector, maturity, or pack code changes.

## Motivation / context

Epic [#85](https://github.com/chinmay-sawant/codehound/issues/85) scopes catalog-honesty work
for the six file-permission rules in
`src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs`.
Parent audit §2.11 inventories these as the next long-tail family after CWE-250/252/552.

Phase 1 (#86) must freeze evidence **before** Phase 2 detector tightening or Phase 3 real-module
canary so dispositions are not justified solely by fixtures firing.

Plan: `plans/v0.0.5/cwe-file-permissions-trust.md`  
Evidence: `plans/v0.0.5/cwe-file-permissions-evidence.md`

## Changes

### Plans / evidence

- Add `plans/v0.0.5/cwe-file-permissions-trust.md` (full Phase 1–4 tranche plan; Phase 1 boxes checked).
- Add `plans/v0.0.5/cwe-file-permissions-evidence.md` with:
  - Per-rule sink/API, primary signal, SourceIndex deps, negatives, finding-span
  - Metadata, registry, catalogue, maturity, pack membership confirmation
  - Fixture oracle result (`go_cwe_detector_fixtures` green)
  - Six-rule `--only` multiset on stdlib+frameworks fixtures (vulnerable 12 / safe 0)
  - Disposition candidates (not applied):
    - **structural candidate:** CWE-277
    - **fixture-only candidate:** CWE-276, CWE-278, CWE-279, CWE-281, CWE-921
  - Runtime maturity remains Heuristic for all six

### Code

- None (by design).

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None — documentation only |
| **API / CLI** | None |
| **Dependencies** | None |
| **Binary size / build time** | Unchanged |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

## Test plan

- [x] `cargo test --locked --test go_cwe_detector_fixtures` — **4 passed**
- [x] Six-rule fixture multiset recorded (debug binary; same detectors as release for this baseline)
- [ ] `make lint` — skipped (no Rust changes)
- [ ] Real-module canary (gopdfsuit / monsoon / go-retry) — **Phase 3**, not this PR

## Related issues

- Closes #86
- Relates to #85
