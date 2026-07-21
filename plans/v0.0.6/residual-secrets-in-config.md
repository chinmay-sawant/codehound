# v0.0.6 — R1 secrets_in_config trust (CWE-260 / 455)

> **Class:** B (catalog residual)  
> **Issue:** [#158](https://github.com/chinmay-sawant/codehound/issues/158) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Seam:** `src/lang/go/detectors/cwe/domains/configuration/secrets_in_config.rs`  
> **Deferred from:** Phase 3 C2 (config_hardcoding only)

## Checklist
- [x] Freeze signals / fixtures / maturity for CWE-260, CWE-455
- [x] Env-requiredness vs project-agnostic security contract
- [x] Disposition per rule; optional oracle-safe rewrite
- [x] Fixtures green + real-module canary
- [x] Integrator maturity/NEEDLES if FO
