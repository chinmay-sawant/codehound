# chore(gates): refresh G1/G2 reopen evidence (keep deferred)

## Summary

- Re-run **G2** CWE-277 release canary and **G1** BP-71 static sampling on the pinned decision-quality corpus after Class B + P1.
- **Both reopen gates still fail** (0 actionable real-module signal).
- Docs-only: record evidence; **no** Structural promotion, **no** new BP rules.

---

## Motivation / context

Class A streams [#152](https://github.com/chinmay-sawant/codehound/issues/152) (G1) and [#153](https://github.com/chinmay-sawant/codehound/issues/153) (G2) under epic [#151](https://github.com/chinmay-sawant/codehound/issues/151).

Prior Phase 5 outcomes already deferred both; this refresh confirms the same decision on current `master` (`4b3ec9b`).

---

## Results

| Stream | Method | Result | Product action |
|--------|--------|--------|----------------|
| **G2** CWE-277 | `--only CWE-277` on 5 pins | **0 / 376** | Keep **Heuristic**; no Structural |
| **G1** BP-71 | Static allowlist sampling | **0 actionable** (idiomatic `_, err :=` Copy/Write/Sscanf only) | **No detector** |

Evidence:

- [`evidence-g2-cwe-277-reopen.md`](./evidence-g2-cwe-277-reopen.md)
- [`evidence-g1-bp-reopen.md`](./evidence-g1-bp-reopen.md)

---

## Changes

| Path | Change |
|------|--------|
| `plans/v0.0.6/evidence-g1-bp-reopen.md` | New G1 refresh |
| `plans/v0.0.6/evidence-g2-cwe-277-reopen.md` | New G2 refresh |
| `plans/v0.0.6/gated-g1-bp-expansion.md` | Status + checklist notes |
| `plans/v0.0.6/gated-g2-cwe-277-structural.md` | Status + checklist notes |
| `plans/v0.0.6/pending-work.md` | Note refreshed deferral |

---

## Explicit non-actions

- No `maturity.rs` Structural flip for CWE-277  
- No BP-71 / BP-66+ detector or registry entries  
- No pack membership changes  

---

## Test plan

- [x] Release binary canary `--only CWE-277` (0/376)
- [x] Static BP-71 sampling on five pins
- [x] Docs committed

---

## Related issues

- Explicitly re-defers #152 and #153 with fresh evidence (gates unmet)  
- Relates to #151
