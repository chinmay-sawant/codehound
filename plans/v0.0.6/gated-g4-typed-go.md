# v0.0.6 — G4 Typed Go / go/packages

> **Class:** A (gated)  
> **Issue:** [#155](https://github.com/chinmay-sawant/codehound/issues/155) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md)  
> **Status:** Deferred — Gate A mostly fails (A6 only)

## Checklist

### Gate A (all required)
- [ ] A1 PERF pack typed-mode readiness sign-off
- [ ] A2 Typed-mode honesty ledger
- [ ] A3 Written FN/FP capability contract
- [ ] A4 Accepted architecture sketch
- [ ] A5 Cost measurements accepted
- [x] A6 Non-blocker policy (held)

### Implementation (after Gate A)
- [ ] Optional typed fact layer behind explicit flag
- [ ] Tree-sitter remains primary default
- [ ] Tests + docs: optional, cost, non-default recommended pack

### Explicit non-goals
- [x] No required typed mode for offline/recommended scans
- [x] No go/packages until A1–A6 pass
