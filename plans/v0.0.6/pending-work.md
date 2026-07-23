# v0.0.6 — Pending work backlog

> **Status:** Class B + P1 done; G1 future/deferred; G2 deferred; G3 residual FO (auth_flows) in flight; G4–G6 gated  

> **Parent (closed):** v0.0.5 parallel catalog program ([#105](https://github.com/chinmay-sawant/codehound/issues/105)) and Phase 5 gate eval ([#136](https://github.com/chinmay-sawant/codehound/issues/136) / PR #150)  
> **Day context:** [`../v0.0.5/22072026.md`](../v0.0.5/22072026.md)  
> **Process:** [`../skills/worktree-deleation/SKILL.md`](../skills/worktree-deleation/SKILL.md) when executing batches  
> **GitHub epic:** [#151](https://github.com/chinmay-sawant/codehound/issues/151)

---

## Overview

Everything that remains after v0.0.5 catalog-trust and Phase 5 *evaluation* is listed here as **checklist workstreams**. Nothing in this file is “in progress” until a child issue is actively executed.

Two classes of work:

| Class | Meaning | Start rule |
|-------|---------|------------|
| **A. Gated product (G1–G6)** | Evaluated deferred; needs reopen evidence | Meet criteria in `v0.0.5/phase5-g*-*.md` first |
| **B. Catalog residual slices** | Domain siblings not fully trust-audited | Standard freeze / disposition / canary / maturity |

Optional process items (canary re-runs) are Class C — light chore streams.

---

## GitHub map

| ID | Issue | Local plan |
|----|------:|------------|
| Epic | [#151](https://github.com/chinmay-sawant/codehound/issues/151) | this file |
| G1 | [#152](https://github.com/chinmay-sawant/codehound/issues/152) | [`gated-g1-bp-expansion.md`](./gated-g1-bp-expansion.md) |
| G2 | [#153](https://github.com/chinmay-sawant/codehound/issues/153) | [`gated-g2-cwe-277-structural.md`](./gated-g2-cwe-277-structural.md) |
| G3 | [#154](https://github.com/chinmay-sawant/codehound/issues/154) | [`gated-g3-fo-generalization.md`](./gated-g3-fo-generalization.md) |
| G4 | [#155](https://github.com/chinmay-sawant/codehound/issues/155) | [`gated-g4-typed-go.md`](./gated-g4-typed-go.md) |
| G5 | [#156](https://github.com/chinmay-sawant/codehound/issues/156) | [`gated-g5-advanced-taint.md`](./gated-g5-advanced-taint.md) |
| G6 | [#157](https://github.com/chinmay-sawant/codehound/issues/157) | [`gated-g6-python-catalog.md`](./gated-g6-python-catalog.md) |
| R1 | [#158](https://github.com/chinmay-sawant/codehound/issues/158) | [`residual-secrets-in-config.md`](./residual-secrets-in-config.md) |
| R2 | [#159](https://github.com/chinmay-sawant/codehound/issues/159) | [`residual-sensitive-fields.md`](./residual-sensitive-fields.md) |
| R3 | [#160](https://github.com/chinmay-sawant/codehound/issues/160) | [`residual-auth-flows.md`](./residual-auth-flows.md) |
| R4 | [#161](https://github.com/chinmay-sawant/codehound/issues/161) | [`residual-auth-tokens.md`](./residual-auth-tokens.md) |
| R5 | [#162](https://github.com/chinmay-sawant/codehound/issues/162) | [`residual-credential-expiration.md`](./residual-credential-expiration.md) |
| R6 | [#163](https://github.com/chinmay-sawant/codehound/issues/163) | [`residual-credential-reset-recovery.md`](./residual-credential-reset-recovery.md) |
| R7 | [#164](https://github.com/chinmay-sawant/codehound/issues/164) | [`residual-lifecycle-integrity.md`](./residual-lifecycle-integrity.md) |
| R8 | [#165](https://github.com/chinmay-sawant/codehound/issues/165) | [`residual-injection-resource-generalize.md`](./residual-injection-resource-generalize.md) |
| P1 | [#166](https://github.com/chinmay-sawant/codehound/issues/166) | [`process-canary-and-pack-pilot.md`](./process-canary-and-pack-pilot.md) |

### Epic progress checklist

#### Class A — Gated (defer until reopen)
- [ ] #152 G1 Broad BP-66+ / BP-71 — **reopen fail 2026-07-23** ([evidence](./evidence-g1-bp-reopen.md))
- [ ] #153 G2 CWE-277 Structural — **reopen fail 2026-07-23** ([evidence](./evidence-g2-cwe-277-reopen.md))
- [x] #154 G3 Further FO residual (auth_flows 305–309/620/836 FO) — true-gen still deferred
- [ ] #155 G4 Typed Go / `go/packages`
- [ ] #156 G5 Advanced taint ceilings
- [ ] #157 G6 Python multi-rule catalog

#### Class B — Catalog residual trust slices
- [x] #158 R1 secrets_in_config (CWE-260 / 455)
- [x] #159 R2 sensitive_fields (CWE-201 / 213)
- [x] #160 R3 auth_flows (bounded subfamily)
- [x] #161 R4 auth_tokens (bounded subfamily)
- [x] #162 R5 credential expiration / aging
- [x] #163 R6 credential reset / recovery
- [x] #164 R7 lifecycle_and_integrity
- [x] #165 R8 injection resource true generalization (619/917 beyond FO) — keep FO

#### Class C — Process
- [x] #166 P1 Canary corpus re-run + recommended-pack pilot after catalog batches

---

## Recommended execution order

1. ~~**R1–R4**~~ — **done** (PR #171 / issues #158–#161)  
2. ~~**R5–R7**~~ — **done** (R5–R8 integration / issues #162–#165)  
3. ~~**R8 / G3**~~ — **done** (keep FO; no uplift in #165)  
4. **G2 / G1** — only after real-module hits (next if reopen evidence exists)  
5. **G4 / G5 / G6** — strategic; external demand + architecture gates  
6. ~~**P1**~~ — **done** (canary + recommended-pack pilot post R1–R8)  

Do **not** schedule all Class A at once. Prefer ≤4 worktrees per residual batch + one integration.

---

## Shared rules (every residual stream)

- [ ] Freeze primary signals / negatives / fixtures before rewrites  
- [ ] Oracle-safe detector changes only (fixture suite green)  
- [ ] Per-rule disposition: Structural candidate / Heuristic keep / fixture-only / retire  
- [ ] Canary on pinned corpus (`v0.0.5/canary-corpus.md`)  
- [ ] Integrator owns shared `maturity.rs` / `source_index.rs` / audit unless issue says otherwise  
- [ ] Structural bar: `v0.0.5/cwe-catalog-trust-audit.md` §1.3  

---

## References

- v0.0.5 program: [`parallel-catalog-program.md`](../v0.0.5/parallel-catalog-program.md)  
- Phase 5 gates: [`phase5-gated-work.md`](../v0.0.5/phase5-gated-work.md)  
- Phase 5 eval evidence: `phase5-g{1,2,4,5,6}-*.md`, `phase5-g3-fo-residual-plan.md`  
- Day ledger: [`22072026.md`](../v0.0.5/22072026.md)  
- ROADMAP: [`../../ROADMAP.md`](../../ROADMAP.md)  
