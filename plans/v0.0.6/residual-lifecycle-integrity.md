# v0.0.6 — R7 lifecycle_and_integrity trust

> **Class:** B (catalog residual)  
> **Issue:** [#164](https://github.com/chinmay-sawant/codehound/issues/164) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Seam:** `general_security/lifecycle_and_integrity/`  
> **Deferred from:** Phase 2 B4 (privilege_escalation only)

## Checklist
- [x] Select family with clear sink + safe fixtures (lifecycle / plugins / runtime_state)
- [x] Defer topology / whole-program ownership rules
- [x] Freeze + disposition + canary

**Selected leaf:** `plugins.rs` (CWE-618, 829, 1125).
**Deferred leaves:** `lifecycle.rs` (lock/lifetime/worker topology), `runtime_state.rs` (cross-request covert channel + inconsistent failure topology).
**Evidence:** [`evidence-r7-lifecycle-integrity.md`](./evidence-r7-lifecycle-integrity.md) · **PR body:** [`pr-r7-lifecycle-integrity.md`](./pr-r7-lifecycle-integrity.md)
