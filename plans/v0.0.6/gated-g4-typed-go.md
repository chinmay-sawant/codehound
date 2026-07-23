# v0.0.6 — G4 Typed Go / go/packages

> **Class:** A (gated)  
> **Issue:** [#155](https://github.com/chinmay-sawant/codehound/issues/155) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md)  
> **Gate A package:** [`evidence-g4-gate-a.md`](./evidence-g4-gate-a.md)  
> **Status:** Gate A **PASS** 2026-07-23 — product implementation still open

## Checklist

### Gate A (all required)
- [x] A1 PERF pack typed-mode readiness sign-off — [`evidence-g4-gate-a.md`](./evidence-g4-gate-a.md) §A1
- [x] A2 Typed-mode honesty ledger — §A2
- [x] A3 Written FN/FP capability contract — [`g4-typed-capability-contract.md`](./g4-typed-capability-contract.md)
- [x] A4 Accepted architecture sketch — [`g4-typed-architecture.md`](./g4-typed-architecture.md)
- [x] A5 Cost measurements accepted — §A5 (external `packages.Load` probe)
- [x] A6 Non-blocker policy (held)

### Implementation (after Gate A)
- [ ] Optional typed fact layer behind explicit flag
- [ ] Tree-sitter remains primary default
- [ ] Tests + docs: optional, cost, non-default recommended pack
- [ ] New scoped impl tranche (pilot rule max) — do not bulk under docs-only PR

### Explicit non-goals
- [x] No required typed mode for offline/recommended scans
- [x] No go/packages **product** integration until Gate A pass **and** impl tranche
