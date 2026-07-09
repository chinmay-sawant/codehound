# Enhanced PERF Patterns — V2.0.0

## Summary

Close the gap between **profiler-driven hot-path smells** and what CodeHound PERF rules actually fire on. A cross-check of real high-throughput Go workload hotspots (alloc/copy/flate/crypto/table-write families) against existing PERF-001–224 revealed systematic blind spots: buffer churn, missing compress writer pools, un-Grow'd builders with estimable size, static recompute of pure functions per call, and crypto-setup reuse. This batch tightens 10 existing rules and ships 8 new detectors (PERF-225–231, 233) — all verified 1:1 against their originating themes on production Go code.

## What Changed

### Tighten Existing (Phase B) — Same IDs, Broader Matching

| Rule | What changed |
|------|-------------|
| PERF-018 | Unnecessary slice copy — removed fixture-only `processItems` hard-coding |
| PERF-027 | Missed sync.Pool reuse — widened beyond request-path, added large `make([]byte, N≥4KiB)` in loops |
| PERF-032 | String/byte conversion — expanded beyond obvious loop conversions |
| PERF-054 | strings.Builder Reset — was gin-only, now general hot path |
| PERF-109 | Map key recompute — expanded expensive markers + status → Implemented |
| PERF-192 | Map without size hint — facts-based size-opportunity detection |
| PERF-215 | Buffer/Builder without pre-sizing — name-agnostic receiver tracking |
| PERF-217 | Static computation rebuilt per op — dropped HTTP-only gate |
| PERF-218 | Pool without per-CPU sharding — broadened beyond handler files |
| PERF-219 | Oversized object returned to pool — removed `func Recycle`-only coupling |

Key principle: **hot path ≠ HTTP only**. A shared `is_hot_path` helper (loop membership ∨ hot function name ∨ legacy handler shape) replaced what was an HTTP-centric gate.

### New Rules (Phase C) — PERF-225+

| ID | Name | Severity | What it detects |
|----|------|----------|-----------------|
| **PERF-225** | Redundant Large Slice Clone | High | Double `slices.Clone` / `append(nil, …)` on same buffer |
| **PERF-226** | Post-Producer Buffer Re-Copy | High | `make`+`copy` immediately after `Bytes()`/`Close()` |
| **PERF-227** | Compress Writer Without Pool | High | Unpooled `flate.NewWriter` / `zlib.NewWriter` / `gzip.NewWriter` in hot functions |
| **PERF-228** | Parallel Fan-Out Tiny Workset | Low | `errgroup` fan-out over N≤2 element composite literals |
| **PERF-229** | Intermediate String On Byte Append | Medium | `strconv.Itoa` → `append(dst, s...)` instead of `AppendInt` |
| **PERF-230** | Pure Fn Re-Eval In Loop | Medium | Loop-invariant pure helpers (`parse*`, `measure*`) called per iteration |
| **PERF-231** | PEM/Key Parse On Hot Path | High | `pem.Decode` / `x509.Parse*` inside hot functions (not init/Once) |
| **PERF-233** | Slow Compress Level On Hot Path | Medium | `DefaultCompression` / `BestCompression` on hot encode where `BestSpeed` suffices |

**Merged:** PERF-232 (Crypto Scaffold Rebuilt) → folded into PERF-231.

## Architecture & Implementation

**Phases A–E:**

- **A** — Shared `is_hot_path` / `function_name_is_hot` in `src/lang/go/detectors/perf/common.rs`
- **B** — Tightened 10 rules with broader fixtures and facts-based matching
- **C** — 8 new rules in `ruleset/golang/chunks/perf-225-232.json`
- **D** — Optional fold decisions (PERF-228 shipped, PERF-233 reclassified from OOS)
- **E** — Closeout: `make run-perf-enhanced`, CHANGELOG, 1:1 mapping doc

**Detector placement:**

- `…/stdlib_misuse/caches_and_allocation.rs` — PERF-215/217/218/219
- `…/stdlib_misuse/copies_and_compress.rs` — PERF-225/226/227/228/229/230/231/233
- Targeted edits to 018, 027, 032, 054, 109, 192 in their existing modules

## 1:1 Verification (on gopdfsuit production code)

| Theme | PERF | Evidence |
|-------|------|----------|
| Double `slices.Clone` | 225 | `generator.go:1490` |
| Post-compress `make`+`copy` | 226 | `generator.go:822`, `metadata.go:325` |
| Pre-grow Buffer/Builder | 215 | 15 sites across `generator.go`, `metadata.go`, `font/registry.go`, `outline.go`, `draw.go` |
| ICC/static recompute | 217 | `metadata.go:312`, `pdfa.go:355` |
| Compress without pool | 227 | `form/xfdf.go:1221`+`:1584`, `redact/secure.go:233` |
| Slow compress level | 233 | Same xfdf/redact sites |
| PEM parse on sign | 231 | `signature.go:133` |
| drawTable re-eval | 230 | `draw.go:529–657` (parseProps, resolveFontName, etc.) |

**All 11 themes with static-analyzable shape fire on real code.** 1 (num-emit) was already fixed; 1 (klauspost/GOMAXPROCS/GOMEMLIMIT/compliance) is permanent OOS.

## Verification

```bash
cargo test --test go_perf_detector_integration     # green (4/4)
cargo test --test go_perf_ruleset_audit             # green
cargo test --test go_perf_registry_generation       # green
cargo test --test fixture_manifest_integration_inventory  # green
make run-perf-enhanced                              # text findings, not buried by BP/CWE
```

No catastrophic noise on `tests/fixtures/go/perf_real_world/clean_go_file.txt`.

## Permanent Non-Goals (OOS)

- Third-party compress (klauspost) — dependency choice, not a static anti-pattern
- GOMAXPROCS / GOMEMLIMIT — runtime / deployment tuning, not AST
- Product compliance (PDF/A, signatures required) — policy, not performance
- CWE / BP catalogue changes — different product surface
- Auto-`--fix` for new rules — separate engineering plan

## Checklist

- [x] Gap matrix reviewed
- [x] 10 existing rules tightened with broader fixtures
- [x] 8 new rules shipped (225–231 + 233), 232 merged into 231
- [x] Shared `is_hot_path` helper centralized in `common.rs`
- [x] Chunk file `perf-225-232.json` + registry + detectors + fixtures
- [x] 1:1 verification on real Go codebase (gopdfsuit)
- [x] Integration + audit + generation tests green
- [x] OOS documented
- [x] `make run-perf-enhanced` for focused visibility
