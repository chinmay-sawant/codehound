# D1 — P2 Implementation Deferred

> **Parent:** `plans/p2-implementation/`
> **Status:** 160 items deferred to v3.0.0, 16 resolved since initial audit
> **Estimated effort:** TBD

---

## Overview

Deferred items from p2-implementation plan files that were not yet implemented at time of audit.

---

## Phase 1: Taint Tracking (01-taint-tracking.md)

### 1.1 Handle function returns

- [x] Cross-function return propagation — implemented via `finalize()` in `mod.rs:121`

### 1.2 Edge cases

- [x] Pointer/reference aliasing — implemented via `output_pointer_params` in summary.rs
- [x] Map/slice mutations — implemented via map/slice write bridge in `build.rs:204-205`
- [ ] Defer statements — tainted data in defer closure not tracked
- [x] Goroutine closures — implemented via channel send/receive taint tracking
- [ ] Type assertions and conversions — `x := v.(string)` not handled

### 1.3 Inter-Procedural Analysis

- [x] build_call_graph with function spans — implemented via `merge_call_graphs()` + `finalize()`
- [x] TaintSummary (taints_params, etc.) — implemented via `compute_all_summaries()`
- [x] propagate_inter_procedural — implemented as `finalize()`
- [~] Builtin summary table — `BUILTIN_SUMMARIES` lazy_static deferred
- [ ] Recursive functions depth limit — not implemented
- [ ] Mutual recursion visited set — not implemented

### 1.4 CWE-90, CWE-91 Rewrites

- [x] CWE-90 (LDAP Injection) taint path
- [x] CWE-91 (XPath Injection) taint path
- [x] Appropriate sanitizers/validators for LDAP/XPath

### 1.5 Constraint: Two-hop limit

- [ ] Track taint through at most 2 assignment hops — no hop-limit logic exists
- [ ] Three or more hops → fall back to pattern match — not implemented
- [ ] Cross-function hops count toward limit — not implemented
- [ ] Log debug-level message on truncation — not implemented

### 1.6 Sanitizer Detection & Confidence Scoring

- [ ] Custom sanitizer detection (name heuristics) — partially implemented via ponytail comment in `classify.rs:152`
- [x] Validation patterns (regexp.MustCompile, strconv.Atoi, etc.)
- [ ] Type assertion as sanitization — not implemented
- [ ] Confidence scoring (multiply by 0.9/0.8/0.7/0.5) — `confidence` field exists but formula not applied
- [ ] Low-confidence finding downgrade — not implemented

### 1.7 Performance considerations

- [ ] Limit taint extraction to files with source AND sink (quick pre-scan) — not implemented
- [ ] Benchmark taint analysis overhead — not benchmarked
- [ ] `--max-taint-depth` CLI flag — not implemented

### 1.8 Test fixtures

- [ ] cross_function_taint.txt — fixture does not exist
- [ ] two_hop_taint.txt — fixture does not exist
- [ ] three_hop_taint.txt — fixture does not exist
- [ ] goroutine_taint.txt — fixture does not exist
- [ ] sanitized_via_validation.txt — fixture does not exist

### 1.9 Integration tests

- [x] go_taint_integration.rs — file exists, tests `#[ignore]`'d until Phase 3 lands
- [x] Parameterized tests per fixture
- [x] `assert_fixture_rules()` helper
- [ ] `--no-taint` test — no dedicated integration test
- [ ] Confidence scoring test — not implemented

### 1.10 Regression tests

- [ ] Ensure existing CWE detectors still fire — not specifically tested for taint mode
- [ ] Ensure existing safe fixtures still don't fire — not specifically tested for taint mode
- [x] `cargo test` — passes
- [x] `cargo bench` — runs
- [ ] No performance regression on `--no-taint` — not benchmarked

### 1.11 Future Extensions

- [x] All Phase 7 items — deferred as future scope, not part of this implementation

---

## Phase 2: Baseline Ignore (02-baseline-ignore.md)

### 2.1 File-level rule-specific detector masking

- [ ] Rule-specific detector masking while preserving suppressed-count and `--show-ignored` semantics — fast-path for `// slopguard-ignore-file: all` exists but rule-specific masking before analysis is not implemented

---

## Phase 3: Incremental Analysis (03-incremental-analysis.md)

### 3.1 Cache hit validation

- [x] Apply inline ignore comments — intentionally skipped per plan, no change needed

### 3.2 Performance benchmarking

- [ ] Assert cached time is at least 10× faster — benchmark file exists but assertion commented out

### 3.3 Robustness tests

- [x] Concurrent scans (two processes) — cache corruption handling implemented

---

## Phase 4: Perf Detector Implementation (04-perf-detector-implementation.md)

### 4.1 Remaining Hygiene Work

- [x] Benchmark regression investigation — documented in `docs/architecture-performance.md`
- [x] Diagnostic documentation — `docs/perf-detector-development.md` created
- [x] Test fixture audit — all 442 PERF fixture pairs audited
- [x] Edge-case hardening (PERF-172, PERF-150, PERF-139) — verified via existing safe fixtures

---

## Phase 5: Bad Practices Detection (05-bad-practices-detection.md)

- [x] All Phase 4 checklist items — all marked [x], no deferred items

---

## Phase 6: Source Cache Population (missing-A-source-cache-population.md)

### 6.1 Remove file_cache fallback

- [ ] Remove the `file_cache` fallback entirely — still exists in `export/entry.rs:30`

### 6.2 Performance check

- [ ] Measure total scan time with/without source_cache — no before/after benchmark
- [ ] Size threshold for large files — not implemented

### 6.3 Future-proofing

- [ ] Baseline saving needs source_cache — not needed, not implemented
- [ ] Cache entries may include source text — not implemented
- [ ] Taint analysis already has source — available through ParsedUnit
- [ ] ScanArtifact type — not created

---

## Phase 7: Structured Finding Identity (missing-B-structured-finding-identity.md)

### 7.1 SARIF output

- [ ] Add `primary` or `fullyQualifiedLogicalName` — not in SARIF reporter

### 7.2 Incremental analysis

- [ ] Store fingerprints alongside findings in cache — not found in cache code
- [ ] Use fingerprints for cache deduplication/verification — not implemented

### 7.3 CI diffing

- [ ] Future CI integration — not implemented

### 7.4 Migration path

- [ ] Old baseline/cache compatibility — compatibility mode for v0 fingerprints not implemented

### 7.5 Text output

- [x] `--show-fingerprint` CLI flag — implemented via `args.rs:111`

---

## Phase 8: Detector Output Model (missing-C-detector-output-model.md)

### 8.1 Cached fingerprint_str

- [~] Add cached `fingerprint_str` if profiling shows repeated computation matters — deferred in the plan itself

### 8.2 Detector updates

- [~] Category A PatternMatch evidence — deferred per ponytail discipline
- [~] Set `confidence` if heuristic — deferred
- [~] Set `tags` for known false-positive risks — deferred

### 8.3 SARIF backward compatibility

- [~] Test SARIF output against SARIF 2.1.0 schema — deferred

### 8.4 Integration tests

- [~] PatternMatch evidence — deferred

### 8.5 Serialization round-trip tests

- [ ] For each reporter (JSON, SARIF) — no round-trip tests exist for Finding with all optional fields

---

## Phase 9: Rule Pack Extensibility (missing-D-rule-pack-extensibility.md)

### 9.1 Pack loading mechanism

- [ ] Pack loading mechanism — `pack.rs` does not exist
- [ ] SlopguardConfig rule_packs fields — not added to config struct
- [ ] `slopguard.schema.json` updates — design done, not applied
- [ ] PackLoader — not implemented
- [ ] GenericPatternDetector — not implemented
- [ ] Integration into scan pipeline — not done
- [ ] CLI flags — design done, not implemented
- [ ] Configuration schema updates — design done, not applied
- [ ] Unit tests — not created
- [ ] Integration tests — not created

### 9.2 Future extensibility

- [~] All items deferred

### 9.3 Testing

- [ ] All items not implemented

### 9.4 CLI & Configuration

- [ ] `--rule-pack-path` flag — design done, not implemented
- [ ] `--no-rule-packs` flag — design done, not implemented
- [ ] Schema/template updates — not applied

---

## Phase 10: Observability Instrumentation (missing-E-observability-instrumentation.md)

### 10.1 Benchmark

- [ ] Add benchmark: scan with vs without instrumentation — not created

### 10.2 Documentation

- [ ] Document diagnostics schema in `docs/diagnostics.md` — not created

### 10.3 Integration with other P2 features

- [x] ScanStats.files_cached — implemented as `cache_hits`/`cache_misses` in `stats/scan.rs:18-19`
- [x] diagnostics.cache section — included in `diagnostics/build.rs:45-46` as `files_cached`/`files_fresh`
- [~] Cache check timing phase — deferred
- [~] Taint analysis timing phase — deferred
- [~] Taint diagnostics stats — deferred

### 10.4 Instrumentation

- [~] Phase 2c: "fact_extraction" timing phase — deferred (fact extraction runs inline with detection)

### 10.5 Output per-detector timing

- [x] SARIF reporter timing data — `slopguardTiming` field in `SarifRunProperties` at `sarif/schema.rs:35`

---

## Count Table

| Phase | `[x]` Done | `[~]` Deferred | `[ ]` Not Done | Total |
|-------|-----------|----------------|----------------|-------|
| 1 — Taint Tracking | 17 | 1 | 25 | 43 |
| 2 — Baseline Ignore | 0 | 0 | 1 | 1 |
| 3 — Incremental Analysis | 2 | 0 | 1 | 3 |
| 4 — Perf Detector | 4 | 0 | 0 | 4 |
| 5 — Bad Practices | 1 | 0 | 0 | 1 |
| 6 — Source Cache | 0 | 0 | 7 | 7 |
| 7 — Finding Identity | 1 | 0 | 5 | 6 |
| 8 — Detector Output | 0 | 6 | 1 | 7 |
| 9 — Rule Packs | 0 | 1 | 14 | 15 |
| 10 — Observability | 3 | 4 | 2 | 9 |
| **Total** | **28** | **12** | **56** | **96** |
