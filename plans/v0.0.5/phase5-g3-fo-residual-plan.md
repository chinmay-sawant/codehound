# Phase 5 G3 — Fixture-only residual / generalization checklist plan

> **Issue:** [#139](https://github.com/chinmay-sawant/codehound/issues/139) · Relates to epic [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate:** [`phase5-gated-work.md`](./phase5-gated-work.md) G3  
> **Slice shipped:** injection **resource** residual — CWE-619 + CWE-917  
> **Branch:** `chore/phase5-g3-fo-generalization` · PR [#148](https://github.com/chinmay-sawant/codehound/pull/148)  
> **Date:** 2026-07-22  
> **Base SHA:** `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`  
> **Outcome:** **fixture-only** quarantine for CWE-619 / CWE-917 (not Structural generalization)

---

## Purpose

G3 covers two related paths:

1. **Honest FO residual quarantine** — corpus museums still Heuristic by default → `fixture-only` after freeze/canary (this tranche).
2. **True generalization** — replace corpus co-signals with AST/fact primary emit (§1.3) before Heuristic/Structural keep — **not** done for 619/917.

This is the checklist plan for the residual path executed under #139.

---

## Execution checklist

### Completed (2026-07-22)

- [x] Inventory FO-generalization candidates from trust residuals  
  - injection resource (619/917)  
  - secrets_in_config (260/455)  
  - sensitive_fields (201/213)
- [x] Select **one** cohesive family: `injection/resource.rs` (CWE-619 + CWE-917)
- [x] Rationale: Phase 3 C1 deferred sibling after CWE-93 Structural; pure SI museums
- [x] Freeze detector evidence / proof-boundary comments (no oracle break)
- [x] Call-facts primary assessed → **not** oracle-safe without mass-FP
- [x] Maturity: add `CWE-619`, `CWE-917` to `is_fixture_only` + unit tests
- [x] NEEDLES labeled fixture-literal / negative-gate in `source_index.rs`
- [x] Focused fixtures: `go_cwe_detector_fixtures` green
- [x] Canary: `--only CWE-619,CWE-917` on gopdfsuit/monsoon/go-retry → **0/126**
- [x] `make lint` + `make test` (worker: 458 passed)
- [x] Audit note + backlog G3 partial progress
- [x] Filled PR body `pr-phase5-g3-fo-generalization.md`
- [x] Explicit non-action: no bulk FO catalog flip; no Structural without §1.3

### Deferred siblings (not this PR)

- [ ] secrets_in_config CWE-260 / CWE-455 FO or rewrite tranche
- [ ] sensitive_fields CWE-201 / CWE-213 FO or rewrite tranche
- [ ] Other FO museums still default-Heuristic until audited

### Remaining for *true* generalization of 619/917

- [ ] Ownership / dataflow model for cursor Close pairing without exact `rows` name
- [ ] Generalized template/SQL concatenation proof without exact `"report"` / `{{.Title}} where `
- [ ] Renamed near-miss negatives + real-module evidence
- [ ] Only then consider Heuristic keep or Structural under §1.3

---

## Disposition table (shipped)

| Rule | Before | After | Primary signal class |
|------|--------|-------|----------------------|
| CWE-619 | Heuristic | **fixture-only** | SI `rows` Query/Next/Close museum |
| CWE-917 | Heuristic | **fixture-only** | SI template name + `{{.Title}} where ` + concat |
| CWE-93 | Structural | Structural (unchanged) | Header residual from Phase 3 C1 |

---

## Canary (worker)

| Repo | Files | Findings |
|------|------:|---------:|
| gopdfsuit | 78 | 0 |
| monsoon | 43 | 0 |
| go-retry | 5 | 0 |
| **Total** | **126** | **0** |

---

## Files touched (G3)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/injection/resource.rs` | Freeze comments |
| `src/lang/go/detectors/cwe/domains/injection/header.rs` | Sibling note |
| `src/rules/maturity.rs` | FO + tests |
| `src/lang/go/detectors/cwe/source_index.rs` | NEEDLES labels |
| `plans/v0.0.5/cwe-catalog-trust-audit.md` | §2.16 / residual note |
| `plans/v0.0.5/pr-phase5-g3-fo-generalization.md` | PR body |

---

## Sources

- [`phase5-gated-work.md`](./phase5-gated-work.md) G3  
- [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md)  
- [`pr-cwe-trust-injection-residual.md`](./pr-cwe-trust-injection-residual.md) (Phase 3 C1 deferred resource)  
- [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3  
- Day ledger: [`22072026.md`](./22072026.md)
