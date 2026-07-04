# P2 Executive Summary

**Goal:** Take SlopGuard from a well-built v0.x prototype (8.5/10) to a production-grade security analyzer (9.5/10).

---

## The 3 Gaps

| # | Feature | Status | Effort |
|---|---------|--------|--------|
| P2.1 | Taint Tracking / Data Flow | All 275 detectors are `source.contains("...")` — zero inter-procedural analysis | 4-12 weeks |
| P2.2 | Baseline / Ignore-Once | Run on a legacy repo → thousands of findings. No way to say "these are known." | 1-2 weeks |
| P2.3 | Incremental Analysis | Re-parses every file every run. No disk cache. | 2-3 weeks |

## Recommended Build Order

1. **P2.2 Baseline** — unblocks adoption on real codebases. Lowest effort, highest ROI.
2. **P2.3 Incremental** — makes everything faster. Required for CI viability.
3. **P2.1 Taint Tracking** — core correctness. Single biggest gap between SlopGuard and a real security analyzer.

## 9.5/10 Requires

- Taint tracking (P2.1) — the core analysis gap
- Baseline/ignore (P2.2) — the adoption blocker
- Incremental (P2.3) — the CI performance requirement

## Comparable Tools

No single open-source Go security linter has all three. Each exists in a different tool:

| Feature | Tool that has it | Caveat |
|---------|-----------------|--------|
| Taint Tracking | **CodeQL** | Deep inter-procedural data flow, query-based (not a linter) |
| Baseline/Ignore | **Semgrep** | `--baseline-commit` + inline `nosemgrep`, also has experimental taint mode |
| Incremental | **Ruff** (Python), **ESLint** (JS) | Both have `--cache`, but not Go tools |
| All three | **Snyk Code** (commercial) | SaaS-only, not open-source |

The niche Slopguard is targeting — a single binary with Go-specialized taint tracking + production-grade CLI UX — doesn't exist in open-source.
