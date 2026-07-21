# v0.0.5 — Phase 5 implementation backlog (G1–G6)

> **Status:** **Gated backlog** — issues open for tracking; **do not implement** a row until its reopen criteria are met.  
> **GitHub epic:** [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate criteria (source of truth for *why* deferred):** [`phase5-gated-work.md`](./phase5-gated-work.md)  
> **Parent program (closed):** epic [#105](https://github.com/chinmay-sawant/codehound/issues/105) / PR #135  
> **Date:** 2026-07-21

---

## Purpose

After catalog-trust Phases 1–4 and **Phase 5 tracking** shipped under #105, product investments that were explicitly **deferred** need durable GitHub parents and a local ledger.

This file is the **implementation backlog** map (issue ↔ gate ↔ docs). It does **not** authorize starting work without reopen evidence.

| Layer | Document / issue | Meaning |
|-------|------------------|---------|
| Tracking (done) | #120 / #121 closed · `phase5-gated-work.md` | Reopen criteria recorded |
| Backlog (this) | **#136** + children #137–#142 | Implementable parents when gates clear |
| Implementation | Future PRs under a child | One G-row at a time |

---

## Epic and sub-issues

| ID | Issue | Title | Gate summary |
|----|------:|-------|--------------|
| — | [#136](https://github.com/chinmay-sawant/codehound/issues/136) | Phase 5 implementation backlog (epic) | Parent only |
| G1 | [#137](https://github.com/chinmay-sawant/codehound/issues/137) | Broad BP-66+ expansion | Real-module pattern + fixtures + canary + overlap |
| G2 | [#138](https://github.com/chinmay-sawant/codehound/issues/138) | CWE-277 Structural promotion | Actionable hit + mode/scope negatives + §1.3 |
| G3 | [#139](https://github.com/chinmay-sawant/codehound/issues/139) | Generalize fixture-only rules | AST/fact primary replaces corpus co-signals |
| G4 | [#140](https://github.com/chinmay-sawant/codehound/issues/140) | Typed Go / `go/packages` | Roadmap Gate #49 A1–A6 |
| G5 | [#141](https://github.com/chinmay-sawant/codehound/issues/141) | Advanced taint (ext pkg / decoder / channels) | FP/FN contract + no fake edges |
| G6 | [#142](https://github.com/chinmay-sawant/codehound/issues/142) | Python catalog investment | Demand + ADR 0005 reverse/amend |

### Progress checklist (mirror of epic)

- [ ] #137 G1 BP-66+
- [ ] #138 G2 CWE-277 Structural
- [x] #139 G3 FO generalization — **partial:** injection resource (CWE-619/917) FO residual landed; other FO families remain open under reopen criteria
- [ ] #140 G4 typed Go
- [ ] #141 G5 advanced taint
- [ ] #142 G6 Python catalog

---

## How to start a child

1. Read the matching **G-row** in [`phase5-gated-work.md`](./phase5-gated-work.md).
2. Post **reopen evidence** on the child issue (links to canary, design, ADR, etc.).
3. Only then implement on a feature branch; keep scope to that G-row.
4. Prefer fixtures + `make lint` / `make test` + real-module canary before maturity/pack changes.
5. Do **not** implement under closed #120 / #121.

**Parallelism:** at most one or two G-rows active; G4/G5 may coordinate but must not smuggle typed mode into taint without Gate A.

---

## Related residual catalog siblings (optional later issues)

Not Phase 5 G-rows, but unfinished **domain slices** from trust batches (open a new issue if prioritized):

| Domain | Done | Deferred sibling |
|--------|------|------------------|
| Injection | CWE-93 (Structural); **CWE-619/917 FO** (G3 / #139) | — (resource residual disposed) |
| Configuration | hardcoding (15 FO siblings) | secrets_in_config 260/455 |
| Credential lifecycle | credentials-in-source | expiration / reset-recovery |
| Response leaks | metadata_leaks | sensitive_fields 201/213 |
| Auth | cookies | auth_flows / auth_tokens |
| Privilege | privilege_escalation | lifecycle_and_integrity |

---

## Cross-links

| Doc | Role |
|-----|------|
| [`phase5-gated-work.md`](./phase5-gated-work.md) | Reopen criteria G1–G6 |
| [`parallel-catalog-program.md`](./parallel-catalog-program.md) | Program ledger (Phase 5 tracking complete) |
| [`roadmap-gates-49.md`](./roadmap-gates-49.md) | Typed Go A\* / Python B\* |
| [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 | Structural bar |
| [`taint-capability-decision.md`](./taint-capability-decision.md) | Taint ceilings |
| [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md) | Go-first / Python |
| [`ROADMAP.md`](../../ROADMAP.md) | Product roadmap |

---

## History

| Date | Event |
|------|--------|
| 2026-07-21 | #105 Phase 5 **tracking** closed with PR #135 |
| 2026-07-21 | Epic **#136** + children **#137–#142** opened; this backlog file created |
| 2026-07-22 | G3 partial: injection resource CWE-619/917 fixture-only residual (`chore/phase5-g3-fo-generalization`) |
