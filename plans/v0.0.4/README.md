# v0.0.4 — Cold-Scan Performance & Quality Gates

> **Status:** Quality gate (missing docs) done; cold-scan performance plan ready  
> **Baseline target:** gopdfsuit cold scan (~78 Go files / ~28k lines)  
> **Measured wall time:** ~5.2s full re-analysis (0 cache hits)

## Documents

| File | Purpose | Status |
|------|---------|--------|
| [`quality-gate.md`](./quality-gate.md) | **`missing_docs` zero-warning policy** — remove clippy carve-out, document public API | **Done** |
| [`cold-scan-performance.md`](./cold-scan-performance.md) | Investigation + checklist for ultra-fast cold scans without correctness loss | Plan ready |

## Quality gate summary (2026-07-16)

- **Issue:** ~207 `missing documentation` warnings on `make test` because docs were only warned outside Clippy.
- **Change:** `#![warn(missing_docs)]` always on; all public items documented.
- **Result:** `make lint` green; **0** missing-docs warnings on `cargo test --no-run`.

## Cold-scan performance snapshot

| Scenario | Wall time | Notes |
|----------|-----------|-------|
| `--profile all --no-cache` | **5.21s** | matches ~5.23s user report |
| `--only 'BP-*' --no-cache` | **4.34s** | ~83% of cold wall time |
| `--no-bp --profile all --no-cache` | **172ms** | CWE + PERF + parse + I/O |
| warm cache hit path | **~14ms** | not the problem |

**Conclusion:** cold-scan latency is dominated by **`GoBadPracticeScan`**, not chunk export, not tree-sitter parse, not CWE/PERF. See the performance plan for implementation phases.
