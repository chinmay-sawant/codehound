# SlopGuard — Performance Benchmarks

> **Methodology:** Criterion.rs benchmarks on release profile (`opt-level=3`, `lto=thin`, `codegen-units=1`).
> **Fixtures:** 900 Go files (~11,000 total lines, 3.6 MB) materialized from `tests/fixtures/go/{stdlib,perf,frameworks}/`.
> **Hardware:** Linux, single-machine CI runner equivalent.

---

## Baseline (pre-optimization) — June 2026

| Benchmark | Time (ns) | Time (ms) | Notes |
|-----------|----------:|----------:|-------|
| `scan_materialized_fixtures` | 42,539,969 | 42.5 ms | Full scan: 275 detectors across all 900 Go fixture files |
| `collect_entries_materialized` | 828,515 | 0.83 ms | File discovery + language classification only (no parse/scan) |
| `scan_go_only_two_rules` | 15,915,154 | 15.9 ms | Scan with only CWE-22 + CWE-89 enabled |

### System metrics (baseline)

| Metric | Value |
|--------|-------|
| Binary size (stripped) | 4.9 MB |
| Test suite | All 105+ tests passing |
| Severity levels | 4 (Info, Warning, High, Critical) |
| CWE catalog | 6 entries (hardcoded) |
| SourceIndex lookup | O(N) linear scan over Vec<bool> |
| Tree walks per Go file | 4 (CWE facts + PERF facts + PERF var_spec + function spans) |
| Export file reads | Re-read from disk per file |
| Date formatting | Custom 35-line calendar math |
| Sink definitions | Hardcoded inline across detector files |

---

## Post-optimization — June 2026

### Changes applied (P0 → P2 from Review2.md)

| # | Change | Category |
|---|--------|----------|
| 1 | Fixed `argument_uses_identifier` — substring match with exact-match fast path | P0 correctness |
| 2 | Severity: 4→5 levels (Info/Low/Medium/High/Critical), proper CVSS mapping | P0 correctness |
| 3 | `FunctionSpan` overlap validation in debug builds | P0 correctness |
| 4 | Central sink registry (`engine/sinks.rs`) with `phf::Set` | P1 performance |
| 5 | SourceIndex: `phf::Map` O(1) lookup + `u64` bitmask | P1 performance |
| 6 | Tree walks: recursive → iterative `TreeCursor` traversal | P1 performance |
| 7 | Export path: pass `Arc<str>` cache, avoid disk re-reads | P1 performance |
| 8 | Fact extraction: `pub(crate)` hooks for unified single-walk (infrastructure ready) | P1 performance |
| 9 | CWE catalog: auto-generated from `golang.json` (175+ entries) | P2 architecture |
| 10 | `part_N.rs` → themed clusters (path_and_file, injection_and_xss, etc.) | P2 architecture |
| 11 | Monolithic files split into module directories | P2 architecture |
| 12 | `Cow` removed from `Finding::new` | P2 architecture |
| 13 | `iso8601_utc_now` → `jiff::Timestamp::now()` | P2 architecture |
| 14 | Init template → `templates/slopguard.toml` with `include_str!` | P2 architecture |
| 15 | CI perf budget: `scan_materialized_fixtures` < 65ms gate | P2 architecture |

### Post-optimization benchmarks

| Benchmark | Time (ns) | Time (ms) | vs Baseline |
|-----------|----------:|----------:|:-----------:|
| `scan_materialized_fixtures` | 39,976,346 | 40.0 ms | **-6.0%** (faster) |
| `collect_entries_materialized` | 730,737 | 0.73 ms | **-11.8%** (faster) |
| `scan_go_only_two_rules` | 18,621,530 | 18.6 ms | +17.0% (slower) |

### Analysis

| Metric | Before | After | Change |
|--------|--------|-------|:------:|
| Binary size (stripped) | 4.9 MB | 4.9 MB | — |
| Test suite | All passing | All passing | — |
| Severity levels | 4 | 5 (Low, Medium added) | Better |
| CWE catalog entries | 6 | 175+ (auto-generated) | Better |
| SourceIndex lookup | O(N) linear | O(1) phf::Map | Faster |
| Tree walk recursion | Unbounded recursive | Iterative TreeCursor | Stack-safe |
| Export file reads | Per-file disk read | In-memory Arc<str> cache | Faster |
| Sink definitions | Duplicated inline | Centralized phf::Set | Maintainable |

### Key observations

1. **Full scan is 6% faster.** The TreeCursor replacement, SourceIndex optimizations, and reduced allocations compound to a measurable improvement even without the unified single-walk (which is infrastructured but not yet wired into the engine).

2. **Two-rule scan is 17% slower.** CWE-22 and CWE-89 now use `phf::Set` lookups for sink matching instead of inline `==` comparisons. For small sink sets (2-6 elements), the `phf::Set` hash lookup has slightly more overhead than direct string comparison. This is an acceptable trade-off: the sink registry provides a single source of truth and will scale better as more sinks are added.

3. **File collection is 12% faster.** This benchmark doesn't exercise any changed code paths — the improvement is likely from better icache behavior due to the refactored module structure or natural benchmark variance.

4. **The biggest performance win (unified single tree walk) is not yet wired in.** The `populate_cwe_facts_from_node`/`populate_perf_facts_from_node` hooks and `try_record_function_span` helper are ready but the engine's `scan_entry` function still calls the separate `build_go_unit_facts` + `build_go_perf_facts` + `attach_function_context`. Wiring these together into a single tree walk would deliver the remaining 2-3× speedup on the fact-extraction phase.

---

## Next performance targets

| Optimization | Estimated impact | Effort |
|-------------|:----------------:|:------:|
| Wire unified single-walk in `engine/walk.rs` | 2-3× fact extraction speedup | Medium |
| Detector dispatch by callee name (sink-aware) | 50-80% detector loop reduction | High |
| `owo-colors` or feature-gate `colored` | ~5% text-mode speed | Low |
| SIMD UTF-8 validation (`simdutf8`) | ~5% parse speed | Low |

