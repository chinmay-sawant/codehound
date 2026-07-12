# D4 — Pending Work Deferred

> **Parent:** `plans/v2.0.0/pending-work/`, `plans/v2.0.0/reports/`
> **Status:** 9 items resolved, 30 deferred to v3.0.0
> **Estimated effort:** TBD

---

## Overview

Deferred pending work items from the v2.0.0 audit across taint tracking, cache/incremental, and cross-cutting workstreams.

---

## Phase 1: Taint Tracking Remaining

### 1.1 Remove Substring Fallback

- [x] Remove substring-fallback in 4 CWE detectors — now delegates to taint-based implementation
- [ ] Update tests to run all 4 CWE integration tests both with and without taint
- [ ] Add `cargo test --all-features` with taint to CI
- [ ] Test that a file with no sources or no sinks does not trigger spurious findings when taint is enabled
- [x] Test that a file with sources but sanitized sinks does not fire — covered by CWE-22-safe.txt

### 1.2 Extended Sanitizer Coverage

- [ ] Add `utf8.ValidString` → `SanitizerKind::Validation`
- [ ] Add `net/url.IsAbs` → `SanitizerKind::URL`
- [ ] Add `strings.HasPrefix`, `strings.HasSuffix`, `strings.Contains` → `SanitizerKind::Validation`
- [ ] Add Gin framework sanitizers: `c.ShouldBind`, `c.ShouldBindJSON`, `c.ShouldBindQuery`
- [ ] Add Echo framework sanitizers: `c.Bind`, `c.BindWith`
- [ ] Add Chi/gorilla/mux source markers: `chi.URLParam`, `mux.Vars`
- [ ] Add test fixtures for each new sanitizer
- [ ] Update `taint_cwe_fixtures_fire_vulnerable_and_silence_safe` to include new sanitizer fixtures
- [ ] Verify that `strconv.Atoi` + SQL query does not fire CWE-89
- [ ] Add test fixture using a custom `sanitizeInput()` function

### 1.3 CLI Flags + Documentation

- [x] Test for taint finding with `show_paths=true` including path details
- [ ] Add `taint` CLI flags to `codehound.schema.json` — config fields exist but CLI flags not tracked in schema

### 1.4 Inter-Procedural Taint Tracking

- [x] Recursion cycle detection with depth cap — IP-007 fixture
- [x] Fixed-point iteration — single-pass propagation in `finalize()`
- [x] Add `SourceKind::Return` — handled via return-source scanning instead
- [ ] Add `SinkKind::DatabaseWrite` — `db.Exec`, `db.Update`, `db.Save`
- [ ] Add `SinkKind::Logging` — `log.Printf`, `log.Println` with user-controlled format strings
- [ ] Add `SinkKind::Redirect` — `http.Redirect` with user-controlled URL
- [x] Recursive call chain fixture — IP-007
- [x] Map/slice mutations — index-expression bridge in `build.rs`
- [ ] Deferred function calls — track defer targets and propagate taint from deferred closures
- [x] Goroutine closures — capture taint at `go func()` creation point

---

## Phase 2: Cache / Incremental Remaining

### 2.1 Configurable Eviction Parameters

- [ ] Add `flush_evicts_to_configured_ratio` test in `tests/engine_cache_store.rs`

### 2.2 Observability

- [ ] Emit `tracing::debug!` for each individual evicted entry (file path + size) in LRU eviction
- [ ] Add test that verifies the eviction log message is emitted

### 2.3 Test-Suite Gaps

- [ ] Update `documents/incremental-cache.md` limitations section to mention concurrent cache test exists

---

## Phase 3: Cross-Cutting Remaining

### 3.1 Observability

- [ ] Per-detector timing on cache-hit path: file read time, filter-cached-findings time, inline-ignore re-application time
- [ ] `TimingSpan` for cache-hit path recording
- [ ] Emit cache timing details in `--diagnostics` and `--debug-timing` output
- [ ] Add `original_detect_duration_ms` field to `CacheEntry`
- [ ] Show "Cache hit saved: Nms total" in `--diagnostics-summary`

### 3.2 Config / Schema

- [ ] Add `severity_overrides: Option<HashMap<String, Severity>>` to `BadPracticesConfig` Rust struct — schema + template have it, but config parsing does not
- [ ] Wire `severity_overrides` into `ScanContext.apply_finding_overrides()` for BP rules

### 3.3 Reporting

- [~] HTML reporter — explicitly deferred from v2.0.0 scope

---

## External: gopdfsuit Optimizations

> Items from `gopdfsuit-optimizations-markdown-review.md` — external project, not validated against CodeHound codebase.

### E.1 Still-Open Engine/HFT Items

- [ ] Further reduce `bytes.growSlice` and peak heap on compliant x10 runs
- [ ] Continue Phase B/C Zerodha 15K work (pdfBuffer zero-grow, page-stream caps, arena sizing, etc.)
- [ ] Keep reducing `drawTable` / shared-layout row replay cost on HFT-heavy paths
- [ ] Continue retail signature-path cleanup
- [ ] Continue xref / slice / glyph-dedupe / batch-emit work

### E.2 Still-Open HTTP/Gin Items

- [ ] Weighted Gin 1,500 req/s — HFT tail, flate cost, JSON ingress remain main ceiling
- [ ] Optional codegen / alternate Sonic decode improvements

### E.3 Still-Open Python/API-Contract Items

- [ ] Large further gains for PyPDFSuit require Go-boundary or API-contract changes
- [ ] Handle/batch/service-mode style APIs
- [ ] HFT-specific Go-side profile harnessing

### E.4 Rejected Optimizations (documented only)

- [ ] Parallel structure-tree build (G3) — regressed throughput
- [ ] Template PDF cache (G4) — misleading benchmarks
- [ ] Aggressive Gin Phase 12 experiments
- [ ] Generic structure-writer abstraction — performance regression
- [ ] Aggressive buffer-retention pool experiments
- [ ] Compress-cache/store ordering experiments
- [ ] HFT TR→TD collapse — invalid compliant output
- [ ] Unbounded key-based shared-row caches — k6/OOM
- [ ] Large per-SM struct-element arena slabs — heap pressure
- [ ] Python JSON-cache in benchmark surface — bypassed real serialization

---

## Count

| Section | Done ([x]) | Not Done ([ ]) | Deferred ([~]) | Total |
|---|---|---|---|---|---|
| Phase 1 — Taint Tracking | 9 | 18 | 0 | 27 |
| Phase 2 — Cache / Incremental | 0 | 4 | 0 | 4 |
| Phase 3 — Cross-Cutting | 0 | 7 | 1 | 8 |
| External — gopdfsuit | 0 | 20 | 0 | 20 |
| **Total** | **9** | **49** | **1** | **59** |
