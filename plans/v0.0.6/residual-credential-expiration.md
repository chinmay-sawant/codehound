# v0.0.6 — R5 credential expiration / aging trust

> **Class:** B (catalog residual)  
> **Issue:** [#162](https://github.com/chinmay-sawant/codehound/issues/162) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Seam:** `credential_lifecycle/key_expiration.rs`, `password_aging.rs`  
> **Deferred from:** Phase 2 B1 (credentials-in-source only)

## Checklist
- [ ] Select expiration **or** aging (not both if large)
- [ ] Audit runtime/deployment assumptions
- [ ] Freeze + disposition + fixtures + canary
