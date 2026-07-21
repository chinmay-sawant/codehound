# v0.0.6 — R2 sensitive_fields trust (CWE-201 / 213)

> **Class:** B (catalog residual)  
> **Issue:** [#159](https://github.com/chinmay-sawant/codehound/issues/159) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Seam:** `information_exposure/response_leaks/sensitive_fields.rs`  
> **Deferred from:** Phase 2 B2 (metadata_leaks only)

## Checklist
- [x] Freeze call_facts / field co-signals
- [x] Generalized sinks vs exact response literals
- [x] Preserve redaction negatives
- [x] Disposition + fixtures + canary
- [x] Integrator maturity if FO
