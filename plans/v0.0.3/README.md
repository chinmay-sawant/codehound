# v0.0.3 — Deferred Work Inventory

All items previously `[ ]` across v0.0.2, p2-implementation, and v0.0.1 plans have been audited against the current codebase. Items that were **implemented** are marked `[x]` in their original files. Items **not yet implemented** are marked `[~]` and catalogued here for v0.0.3.

## Totals

All deferred files have been converted to standardized phase-wise checklist format (D1–D5).

## Totals

| File | `[x]` Done | `[~]` Deferred | `[ ]` Not Done | Total |
|---|---|---|---|---|---|
| D1 — P2 Implementation | 28 | 12 | 56 | 96 |
| D2 — V2 Core | 5 | 0 | 77 | 82 |
| D3 — Anti-Pattern & Review | 5 | 0 | 22 | 27 |
| D4 — Pending Work (CodeHound) | 9 | 1 | 29 | 39 |
| D4 — External (gopdfsuit) | 0 | 0 | 20 | 20 |
| D5 — V0.0.1 Legacy | 2 | 0 | 22 | 24 |
| **Grand Total** | **49** | **13** | **226** | **288** |

> **Note:** 42 additional `[ ]` items remain in 3 files as intentional non-task content: `PR_TEMPLATE.md` (11 template placeholders), `consolidated_pendingtask_02072026.md` (4 strikethrough-skipped), `ultra-audit-report.md` (27 strikethrough-skipped/reverted). These are not actionable work items.

## Deferred Item Index

| # | File | Focus Area |
|---|---|---|
| D1 | `deferred/agent1-p2-implementation.md` | Taint tracking, CWE rewrites, sanitizer scoring, perf detectors, source cache, finding identity, rule packs, observability |
| D2 | `deferred/agent2-v2-core.md` | Fix engine (all phases), taint edge cases, cache eviction, BP severity, confidence scoring, rule-pack extensibility |
| D3 | `deferred/agent3-antipattern-review.md` | Runtime safety, documentation hygiene, testing, API surface, code formatting, performance |
| D4 | `deferred/agent4-pending-work.md` | Taint tracking remaining (substring fallback, sanitizers, CLI, inter-procedural), cache/incremental, cross-cutting, gopdfsuit (external) |
| D5 | `deferred/agent5-v0.0.1.md` | Legacy TODOs, CWE/perf fixtures, SARIF metadata, PR reviews, callee-indexed scheduling, tree-sitter cache |

## Feature plans (v0.0.3)

| Plan | Focus |
|------|--------|
| **[new-bad-practices/](./new-bad-practices/)** | **100 new Go BP rules (BP-66..BP-165)** — checklist plan split by domain; frameworks Gin/Echo/Fiber/Chi/GORM/sqlx; **requires `.txt` snippet fixtures** |

### New bad practices (quick links)

- Master checklist: [`new-bad-practices/CHECKLIST.md`](./new-bad-practices/CHECKLIST.md)
- Scope / linter gaps: [`new-bad-practices/00-gap-and-scope.md`](./new-bad-practices/00-gap-and-scope.md)
- Parts A–F: core → concurrency → HTTP frameworks → data → observability → testing tail
- Implementation order: [`new-bad-practices/07-implementation-order.md`](./new-bad-practices/07-implementation-order.md)

---

## Next Steps

1. Execute **[new-bad-practices](./new-bad-practices/)** in PR-sized batches (see `07-implementation-order.md`).
2. Pick deferred items from any of the D1–D5 files and design them as vertical-slice tickets for other v0.0.3 sprints.
