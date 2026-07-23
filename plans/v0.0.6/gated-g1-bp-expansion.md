# v0.0.6 — G1 Broad BP-66+ / BP-71 expansion

> **Class:** A (gated)  
> **Issue:** [#152](https://github.com/chinmay-sawant/codehound/issues/152) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g1-bp-reopen-evidence.md`](../v0.0.5/phase5-g1-bp-reopen-evidence.md)  
> **Refresh:** [`evidence-g1-bp-reopen.md`](./evidence-g1-bp-reopen.md) (2026-07-23)  
> **Status:** Deferred — 0 actionable canary hits (Phase 5 + 2026-07-23 refresh)

## Checklist

### Reopen gates (all required before code)
- [ ] Non-idiomatic multi-return discard pattern on pinned real modules — **FAIL 2026-07-23** (idiomatic only)
- [ ] Overlap analysis vs BP/CWE/staticcheck/noctx — blocked on pattern
- [ ] Vulnerable + safe fixtures with near-miss negatives — blocked
- [ ] Release canary with agreed FP budget — blocked
- [ ] Scope one BP family (prefer BP-71 if proven) — not proven

### Implementation (after gates)
- [ ] Detector + registry + fixtures
- [ ] Focused + full tests
- [ ] Canary table recorded
- [ ] Disposition in plans/audit

### Explicit non-goals
- [x] No bulk BP-66+ dump without evidence
- [x] No inventing detectors from fixtures only
- [x] 2026-07-23: no BP-71 ship after refresh
