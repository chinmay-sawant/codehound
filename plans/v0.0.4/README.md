# v0.0.4 — Cold-Scan Performance & Quality Gates

> **Status:** Phases 0–6 done  
> **Baseline target:** gopdfsuit cold scan (~78 Go files / ~28k lines)

## Documents

| File | Purpose | Status |
|------|---------|--------|
| [`quality-gate.md`](./quality-gate.md) | `missing_docs` zero-warning policy | **Done** |
| [`cold-scan-performance.md`](./cold-scan-performance.md) | Cold-scan investigation + phased implementation | **Phases 0–6 done** |

## Cold-scan results

| Scenario | Before | After |
|----------|--------|-------|
| Full re-analysis (`make run`, release, 0 cache hits) | **~5.2s** | **~425ms (~12×)** |
| Findings | 943 | **943 (unchanged)** |
| Warm cache hits | ~14ms | **~12–36ms** |

### What fixed the multi-second path

1. **Instrumentation** — per-BP-rule timing (no more “everything is BP-1”).
2. **Short-circuits + cheaper walks** — NEEDLES, `walk_nodes`, single-cursor loops.
3. **Project-level memoization** — `ProjectSnapshot` flags + prewarm (one WalkDir per root).
4. **Parallel preflight** — concurrent read+hash on cache miss path.
5. **Release `make run`** — product timings use optimized binary; `SKIP_BUILD=1` skips cargo when the binary is already built.

### Local commands

```bash
make run
make run RUN_ARGS="--export-context --export-chunks"
make run SKIP_BUILD=1   # no recompile; uses existing target/release/codehound
```
