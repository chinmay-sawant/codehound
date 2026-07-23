# v0.0.6 — G3 Further FO residual / true generalization

> **Class:** A (gated) + residual  
> **Issue:** [#154](https://github.com/chinmay-sawant/codehound/issues/154) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior:** [`../v0.0.5/phase5-g3-fo-residual-plan.md`](../v0.0.5/phase5-g3-fo-residual-plan.md) (CWE-619/917 FO shipped)  
> **Evidence (this tranche):** [`evidence-g3-auth-flows-fo.md`](./evidence-g3-auth-flows-fo.md)  
> **Status:** Residual FO path for R3-deferred auth_flows — **in this PR**; true generalization still open

## Checklist

### Residual FO quarantine (next families)
- [x] Select one FO residual family (not 619/917) — **auth_flows deferred: 305–309, 620, 836**
- [x] Freeze + optional call_facts (oracle-safe) — SI primary; no emit rewrite
- [x] Maturity FO if museum; canary; fixtures
- [x] Audit/ledger update

### Prior deferred siblings (closed via Class B)
- [x] secrets_in_config CWE-260 / CWE-455 — R1 FO
- [x] sensitive_fields CWE-201 / CWE-213 — R2 Heuristic keep
- [x] injection resource 619/917 true-gen attempt — R8 keep FO

### True generalization path (hard) — still deferred
- [ ] Primary emit without corpus path/name/formula co-signals
- [ ] Renamed near-miss negatives
- [ ] Real-module evidence or documented FP boundary (§1.3)
- [ ] Only then Heuristic keep or Structural

### Explicit non-goals
- [x] No bulk FO → Structural catalog flip
