# v0.0.6 — R8 injection resource true generalization

> **Class:** B (hard residual)  
> **Issue:** [#165](https://github.com/chinmay-sawant/codehound/issues/165) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Seam:** `injection/resource.rs` (CWE-619 / 917 already FO in v0.0.5 G3)  
> **Prior:** [`../v0.0.5/phase5-g3-fo-residual-plan.md`](../v0.0.5/phase5-g3-fo-residual-plan.md)
> **Outcome (2026-07-22):** **keep fixture-only** — §1.3 bar not met; see [`evidence-r8-injection-resource.md`](./evidence-r8-injection-resource.md)

## Checklist
- [x] Design proof without exact `rows` / `"report"` / `{{.Title}} where ` emit gates — **attempted; blocked** (ownership/Close pairing; template concat without corpus literals)
- [x] Oracle-safe rewrite + renamed negatives — **not shipped** (would FN today; no ownership/taint primary)
- [x] Real-module evidence or keep FO — **keep FO** (canary 0/126; no promotion hit)
- [x] Only then maturity uplift — **no uplift** (`maturity.rs` untouched; already FO from G3)
