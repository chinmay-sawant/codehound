# v0.0.6 — G2 CWE-277 Structural promotion

> **Class:** A (gated)  
> **Issue:** [#153](https://github.com/chinmay-sawant/codehound/issues/153) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g2-cwe-277-reopen-evidence.md`](../v0.0.5/phase5-g2-cwe-277-reopen-evidence.md)  
> **Status:** Deferred — keep Heuristic (0/376 canary)

## Checklist

### Reopen gates
- [ ] Reviewed actionable real-module hit for CWE-277
- [ ] Mode-variant / scope negatives as needed (`0o777`, umask variants)
- [ ] Audit §1.3 bar fully met
- [ ] Maturity + profile + tests in same change

### Implementation (after gates)
- [ ] Optional oracle-safe mode widening with fixtures
- [ ] Structural allow-list update
- [ ] Re-canary expanded corpus
- [ ] Audit disposition record

### Explicit non-goals
- [x] No Structural flip on zero-hit canary alone
