# v3.0.0 — Deferred Work Inventory

All items previously `[ ]` across v2.0.0, p2-implementation, and v0.0.1 plans have been audited against the current codebase. Items that were **implemented** are marked `[x]` in their original files. Items **not yet implemented** are marked `[~]` and catalogued here for v3.0.0.

## Totals

| Source | Total `[ ]` audited | `[x]` Implemented | `[~]` Initially deferred | `[x]` Since resolved | `[~]` Currently deferred |
|---|---|---|---|---|---|---|
| p2-implementation/ | 1,236 | 1,060 | 176 | 16 | 160 |
| v2.0.0 core | ~151 | ~50 | ~101 | 4 | ~97 |
| v2.0.0 antipattern-remediation + review | 32 | 2 | 30 | 5 | 25 |
| v2.0.0 pending-work + reports | 570 | 509 | 61 | 8 | 53 |
| v0.0.1 (+ missed files) | 24 | 1 | 23 | 1 | 22 |
| **Grand Total** | **~2,013** | **~1,622** | **~391** | **34** | **~357** |

> **Note:** 42 additional `[ ]` items remain in 3 files as intentional non-task content: `PR_TEMPLATE.md` (11 template placeholders), `consolidated_pendingtask_02072026.md` (4 strikethrough-skipped), `ultra-audit-report.md` (27 strikethrough-skipped/reverted). These are not actionable work items.

## Deferred Item Index

Each deferred file below contains the full checklist items with context:

| # | File | Focus Area |
|---|---|---|
| 1 | `deferred/agent1-p2-implementation.md` | Taint tracking phases 2–6, CWE-90/91 rewrites, sanitizer scoring, perf, fixtures |
| 2 | `deferred/agent2-v2-core.md` | Fix engine (all phases), taint Phase C–F edge cases, cache eviction, BP severity, rule-pack extensibility |
| 3 | `deferred/agent3-antipattern-review.md` | Rust anti-pattern remediation, test hygiene, missing docs, error handling |
| 4 | `deferred/agent4-pending-work.md` | Substring fallback removal, sanitizer coverage, cache-hit timing, gopdfsuit optimizations |
| 5 | `deferred/agent5-v0.0.1.md` | v0.0.1 legacy TODOs, fixtures, SARIF metadata, fmt/lint checks, benchmark verification, callee-indexed scheduling, tree-sitter cache |

## Next Steps

Pick deferred items from any of the above files and design them as vertical-slice tickets for v3.0.0 implementation sprints.
