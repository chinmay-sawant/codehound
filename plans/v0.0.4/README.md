# v0.0.4 — Cold-Scan Performance & Quality Gates

> **Status:** Implemented  
> **Baseline target:** gopdfsuit cold scan (~78 Go files / ~28k lines)

## Documents

| File | Purpose | Status |
|------|---------|--------|
| [`quality-gate.md`](./quality-gate.md) | `missing_docs` zero-warning policy | **Done** |
| [`cold-scan-performance.md`](./cold-scan-performance.md) | Cold-scan investigation + phased implementation | **Done (Phases 0–5)** |

## Cold-scan results (2026-07-16)

| Scenario | Before | After |
|----------|--------|-------|
| `--profile all --no-cache` | **5.21s** | **~353ms (~15×)** |
| Findings | 943 | **943 (identical multiset)** |
| Warm cache hits | ~14ms | **~12ms** |

### What fixed the 5s path

1. **Instrumentation** — per-BP-rule timing (no more “everything is BP-1”).
2. **Short-circuits + cheaper walks** — NEEDLES, `walk_nodes`, single-cursor loops.
3. **Project-level memoization** — `is_project_anchor` / project texts / go.mod / imports cached per root (was WalkDir thrashing every file).
4. **Parallel preflight** — concurrent read+hash on cache miss path.

## Quality gate

Public API is fully documented; `#![warn(missing_docs)]` always on; `make lint` enforces it via `-D warnings`.
