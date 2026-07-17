# v0.0.4 — Cold-Scan Performance & Quality Gates

> **Status:** Phases 0–7A done; Phase 8 implementation complete, with normal-workflow variability still under measurement
> **Baseline target:** gopdfsuit cold scan (~78 Go files / ~28k lines)

## Documents

| File | Purpose | Status |
|------|---------|--------|
| [`quality-gate.md`](./quality-gate.md) | `missing_docs` zero-warning policy | **Done** |
| [`cold-scan-performance.md`](./cold-scan-performance.md) | Cold-scan investigation + phased implementation | **Phase 8 latest release observation recorded** |

## Cold-scan results

| Scenario | Before | After |
|----------|--------|-------|
| Full re-analysis (release, 0 cache hits) | **up to 5s** | **229.4ms best observed** (~22×) |
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
make run RUN_PROFILE=release
make run RUN_PROFILE=release RUN_ARGS="--export-context --export-chunks"
make run RUN_PROFILE=release SKIP_BUILD=1 RUN_ARGS="--no-cache" # no recompile; current release binary
```
