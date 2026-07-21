# docs(phase5): G4 typed Go Gate A evaluation (remain deferred)

## Summary

Docs-only evaluation of **Gate A (A1–A6)** for optional typed Go facts / `go/packages` under Phase 5 **G4**. Records evidence as of 2026-07-22, lists blockers, and includes a **minimal architecture sketch** (no code). **Decision: remain deferred** — A1–A5 fail (A2 partial); only A6 (non-blocker policy) passes.

**Closes nothing for implementation.** Relates to #140 · Relates to #136 · Relates to #49.

**No product code, no `Cargo.toml` deps, no `go/packages`, no `--typed` flag.**

---

## Motivation / context

- Gate criteria: [`plans/v0.0.5/roadmap-gates-49.md`](./roadmap-gates-49.md) Gate A  
- G4 tracker: [`plans/v0.0.5/phase5-gated-work.md`](./phase5-gated-work.md)  
- Backlog: [#140](https://github.com/chinmay-sawant/codehound/issues/140) under epic [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
- Prior defer: [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) (#40)  
- Base SHA: `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`  
- Branch: `docs/phase5-g4-typed-go-gate`

Issue #140 asked for Gate A evidence before any typed implementation. This PR is that evidence pass so agents and batch schedulers do not treat G4 as open for `go/packages` work.

---

## A1–A6 summary (2026-07-22)

| # | Criterion | Result |
|---|-----------|--------|
| A1 | PERF pack product trust for typed-mode readiness | **FAIL** — pilot 95% + noise-reduce closed; no typed-mode-ready sign-off |
| A2 | Catalog honesty boundary | **PARTIAL / FAIL for reopen** — trust process exists; no typed-mode honesty ledger |
| A3 | Written FN/FP capability contract | **FAIL** |
| A4 | Architecture sketch (tree-sitter primary) | **FAIL** as accepted design (draft sketch only in eval) |
| A5 | Cost acceptance (toolchain, latency, CI) | **FAIL** — no measurements |
| A6 | Non-blocker policy (not release/recommended dep) | **PASS** (policy retained) |

**Decision: remain deferred.** All of A1–A6 required; not met.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-g4-typed-go-gate-eval.md` | Full evidence table, blockers, design sketch, non-actions |
| `plans/v0.0.5/pr-phase5-g4-typed-go.md` | This PR body |
| `ROADMAP.md` | Tiny link from “Typed Go facts” Later row to G4 eval (discoverability) |

### Code

None.

---

## Out of scope (explicit)

- `--typed` CLI / config implementation  
- `go/packages` / `go/types` integration or prototypes  
- Cargo dependencies for typed analysis  
- Detector rewrites assuming types  
- G5 taint channel/external-package/decoder work  
- Flipping ROADMAP “Typed Go facts” out of Later  

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | None |
| **API / CLI** | None |
| **Tests / canary** | N/A (docs only) |
| **Packs / maturity** | Unchanged |
| **G4 disposition** | Reaffirmed **deferred** with dated evidence |

---

## Test plan

- [x] Docs-only diff (`plans/v0.0.5/` + optional `ROADMAP.md` link)  
- [x] No `src/`, `Cargo.toml`, ruleset, or test changes  
- [x] Cross-links resolve to #140, #136, #49, Gate A, prior defer  
- [ ] Reviewer confirms decision “remain deferred” is unambiguous  

---

## Checklist

- [x] Relates to #140 (G4 evaluation)  
- [x] Relates to #136 (Phase 5 epic)  
- [x] Relates to #49 (Roadmap Gate A)  
- [x] Label: `documentation`  
- [x] Assignee: @me  
- [x] Commit message: `docs(phase5): G4 typed Go Gate A evaluation (remain deferred)`  
