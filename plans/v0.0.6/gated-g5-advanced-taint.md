# v0.0.6 — G5 Advanced taint ceilings

> **Class:** A (gated)  
> **Issue:** [#156](https://github.com/chinmay-sawant/codehound/issues/156) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g5-taint-ceiling-eval.md`](../v0.0.5/phase5-g5-taint-ceiling-eval.md)  
> **Status:** Deferred — pick one capability at a time

## Checklist

### Choose one stream per tranche
- [ ] Channel/goroutine handoffs **or**
- [ ] External-package summaries **or**
- [ ] Decoder-receiver outputs

### Reopen gates
- [ ] Written FP/FN contract for that stream
- [ ] Design without invented unsupported edges
- [ ] Fixtures + integration tests + canary
- [ ] Dependency clarity vs G4 if needed

### Implementation (after gates)
- [ ] Engine change + honesty docs
- [ ] Silence tests for non-goals preserved

### Explicit non-goals
- [x] No fake channel edges
- [x] No whole-program security-grade taint claim
