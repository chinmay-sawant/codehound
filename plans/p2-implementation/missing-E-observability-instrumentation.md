# Missing E — Observability / Diagnostic Instrumentation

> **Parent:** `plans/p2.md` -- "Missing From This P2 Plan" -- Item E
> **Status:** The engine has good error isolation, but lacks operational story around timings, scan summaries, cache hit rates, and rule cost visibility.
> **Estimated effort:** 1-2 weeks.

---

## Overview

Once incremental analysis or larger monorepo workflows are added, performance debugging becomes a product need rather than just a development need. This plan adds structured timing, per-rule cost visibility, scan statistics, and machine-readable output for operational metrics.

---

## Phase 1: Structured Timing Infrastructure

### 1.1 Define timing primitives

- [x] Create `src/engine/timing.rs`
- [x] Define `TimingSpan`:
  ```rust
  pub struct TimingSpan {
      pub name: &'static str,
      pub start: Instant,
      pub duration: Option<Duration>,
  }
  ```
- [x] Define `TimingCollector`:
  ```rust
  pub struct TimingCollector {
      spans: Vec<TimingSpan>,
      enabled: bool,
  }
  ```
- [x] Methods on `TimingCollector`:
  - [x] `new(enabled: bool) -> Self`
  - [x] `start(&mut self, name: &'static str) -> usize` -- returns span index
  - [x] `stop(&mut self, index: usize)` -- records duration
  - [x] `measure<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T` -- convenience wrapper
  - [x] `to_summary(&self) -> TimingSummary` -- aggregate statistics

### 1.2 Define `TimingSummary`

- [x] `TimingSummary` struct:
  ```rust
  pub struct TimingSummary {
      pub total_wall_time: Duration,
      pub phases: Vec<PhaseTiming>,
  }
  pub struct PhaseTiming {
      pub name: &'static str,
      pub duration: Duration,
      pub percentage: f64,
      pub count: usize,       // how many times this phase was entered
  }
  ```
- [x] Serialize to JSON for machine-readable output

### 1.3 Instrument the major pipeline phases

- [x] In `analyze_paths()` (`src/engine/analyzer.rs`):
  - [x] Phase 1: `"file_walk"` -- `collect_entries()` duration
  - [x] Phase 2: `"parse_and_detect"` -- internal scan timing (file_read, tree_sitter_parse, detector_execution)
  - [x] Phase 3: `"sort_results"` -- sorting findings duration
- [x] In `scan_entries_parallel()` (`src/engine/walk.rs`):
  - [x] Phase 2a: `"file_read"` -- cumulative time reading files from disk
  - [x] Phase 2b: `"tree_sitter_parse"` -- cumulative time parsing with tree-sitter
  - [x] Phase 2c: `"fact_extraction"` -- (deferred; fact extraction currently runs inline with detection)
  - [x] Phase 2d: `"detector_execution"` -- cumulative time running all detectors
- [x] In `app.rs::run()`:
  - [x] Phase 4: `"export"` -- exporting context/chunk files
  - [x] Phase 5: `"reporting"` -- formatting and writing output
  - [x] Phase 0: `"config_load"` -- loading and merging configuration

### 1.4 Integration with tracing

- [x] If `tracing` is already in use (`src/main.rs` has `tracing_subscriber::fmt::init()`), respect its span system
- [x] Decision: Use `TimingCollector` (lightweight, no tracing overhead when disabled) for the product feature; keep `tracing` for `RUST_LOG=trace` developer debugging

---

## Phase 2: Per-Rule / Per-Detector Timing (Debug Mode)

### 2.1 Add per-detector timing to `ScanContext`

- [x] Add field to `ScanContext` in `src/core/scan.rs`:
  ```rust
  pub struct ScanContext {
      // ... existing fields ...
      pub debug_timing: bool,  // enabled via --debug-timing flag
      pub diagnostics: bool,   // enabled via --diagnostics flag
  }
  ```

### 2.2 Instrument detector execution

- [x] In `analyze_parsed_unit()` (`src/engine/walk.rs`):
  - [x] If `ctx.collect_detector_timing()`, wrap each detector `run()` call with timing
  - [x] Record duration per rule group (using first rule id as phase name)
  - [x] Aggregate per-detector timings into the per-file `TimingCollector`
  - [x] Aggregate into the global `TimingCollector` after all files processed

### 2.3 Output per-detector timing

- [x] In text reporter (`src/reporting/text.rs`):
  - [x] When `--debug-timing` is set, print a section after findings:
    ```
    --- Detector Timing (top 10) ---
    CWE-89   :  1.23ms  (12.4%)
    CWE-78   :  0.89ms  ( 8.9%)
    CWE-22   :  0.76ms  ( 7.6%)
    ...
    Total detector time: 9.94ms across N phases
    ```
- [x] In JSON reporter:
  - [x] Stats/timing included in envelope `"stats"` object when enabled
- [x] In SARIF reporter:
  - [x] Add timing data as `run.properties.slopguardTiming`

---

## Phase 3: Scan Statistics / Summary

### 3.1 Define `ScanStats` struct

- [x] Create `src/engine/stats.rs`
- [x] Define `ScanStats`:
  ```rust
  pub struct ScanStats {
      pub files_scanned: usize,
      pub files_skipped: usize,
      pub files_errored: usize,
      pub files_cached: Option<usize>,   // reserved for incremental analysis
      pub bytes_scanned: u64,
      pub lines_scanned: u64,

      pub findings_total: usize,
      pub findings_by_severity: HashMap<String, usize>,
      pub findings_by_rule: Vec<(String, usize)>,
      pub findings_suppressed: usize,

      pub rules_executed: usize,
      pub detectors_loaded: usize,

      pub timing: Option<TimingSummary>,
  }
  ```
- [x] Implement `ScanStats::from_result(result: &AnalysisResult) -> Self`
- [x] Implement `ScanStats::merge(&mut self, other: &ScanStats)` for parallel aggregation

### 3.2 Collect statistics during scan

- [x] In `collect_entries()` (`walk.rs`):
  - [x] Count `files_skipped` (entries filtered out by ignore/glob/language)
- [x] In `scan_entry()` (`walk.rs`):
  - [x] Count file size in bytes and lines
  - [x] Count findings per file
  - [x] Count rules executed per file
- [x] In `scan_entries_parallel()` (`walk.rs`):
  - [x] Aggregate per-file stats into global `ScanStats`
  - [x] Count `files_errored`
- [x] In `analyze_paths()`:
  - [x] Build final `ScanStats` and attach to `AnalysisResult`
- [x] Add `stats: Option<ScanStats>` field to `AnalysisResult` in `src/engine/result.rs`

### 3.3 Report statistics

- [x] In text reporter (`src/reporting/text.rs`):
  - [x] Extend the existing footer summary with files scanned/skipped/errored and timing
  - [x] When `--verbose`: show full phase breakdown
- [x] In JSON reporter:
  - [x] Add `"stats"` object to envelope output (`--json-envelope`)
  - [x] NDJSON: no stats record (envelope only)
- [x] In SARIF reporter:
  - [x] Add stats to `run.properties.slopguardScanStats`

---

## Phase 4: Machine-Readable Diagnostics

### 4.1 JSON diagnostics mode

- [x] Add `--diagnostics <FILE>` CLI flag:
  ```rust
  #[arg(long = "diagnostics", help = "Write machine-readable diagnostics JSON to FILE")]
  pub diagnostics: Option<PathBuf>,
  ```
- [x] Format: JSON file containing `tool`, `version`, `timestamp`, `scan`, `findings`, `timing`, `detectors`
  - [x] `cache` section omitted until incremental analysis (P2.3) lands
  - [x] `files_cached` omitted until incremental analysis lands

### 4.2 Integration with CI/CD

- [x] `--diagnostics` file can be consumed by CI pipelines:
  - [x] Plot findings-over-time charts
  - [x] Alert on scan time regressions
  - [ ] Track cache hit rate degradation (deferred to P2.3)
- [ ] Document the diagnostics schema in `docs/diagnostics.md` (deferred)

---

## Phase 5: Keep Instrumentation Low-Overhead When Disabled

### 5.1 Zero-cost when off

- [x] `TimingCollector::new(false)` creates a no-op collector:
  - [x] `start()` returns a dummy index, does nothing
  - [x] `stop()` is a no-op
  - [x] `measure(f)` just calls `f()` without timing
- [x] `ScanStats` collection: only enabled when `--debug-timing` or `--diagnostics`
- [x] Per-detector timing: completely disabled unless `--debug-timing` or `--diagnostics`

### 5.2 Benchmark

- [ ] Add benchmark: scan with instrumentation disabled (default) vs enabled (`--debug-timing`)
- [ ] Target: <1% overhead when disabled, <5% when enabled (only timing, no per-detector)

---

## Phase 6: Testing

### 6.1 Unit tests

- [x] Create `tests/engine_observability_context.rs`
- [x] Test `TimingCollector`:
  - [x] `measure()` returns correct value and records duration
  - [x] Multiple spans aggregated correctly via `TimingSummary::merge`
  - [x] `to_summary()` computes correct totals and percentages
- [x] Test no-op `TimingCollector`:
  - [x] `measure()` returns correct value
  - [x] No timing recorded

### 6.2 Integration tests

- [x] Test `--diagnostics <file>` writes valid JSON
- [x] Test diagnostics file contains expected top-level keys
- [x] Test scan phase timings are non-zero
- [x] Test `--debug-timing` and `--diagnostics` flags parse
- [x] Test `--json-envelope` includes `stats` object (via `ScanStats` in envelope)
- [x] Test default mode: no stats collected

---

## Phase 7: Integration Points with Other P2 Features

### 7.1 With P2.3 (Incremental Analysis)

- [ ] `ScanStats.files_cached` -- populated by incremental analysis cache hits (deferred)
- [ ] `diagnostics.cache` section -- hit rate, miss count (deferred)
- [ ] Timing phases: add `"cache_check"` phase (deferred)

### 7.2 With P2.2 (Baseline)

- [x] `ScanStats.findings_suppressed` -- count of findings filtered by baseline
- [x] Show suppressed count in summary output

### 7.3 With P2.1 (Taint Tracking)

- [ ] Timing phases: add `"taint_analysis"` phase when taint tracking is enabled (deferred)
- [ ] Diagnostics: add taint-specific stats (paths found, sources identified, sinks matched) (deferred)

---

## Dependencies

- `src/core/scan.rs` -- `ScanContext` (adds `debug_timing` field)
- `src/engine/result.rs` -- `AnalysisResult` (adds `stats` field)
- `src/engine/analyzer.rs` -- `analyze_paths()` (instrument phases)
- `src/engine/walk.rs` -- `scan_entries_parallel()`, `scan_entry()` (instrument)
- `src/reporting/text.rs` -- text reporter (show stats in footer)
- `src/reporting/json.rs` -- JSON reporter (add stats to envelope)
- `src/reporting/sarif.rs` -- SARIF reporter (add stats to properties)
- `src/cli/mod.rs` -- CLI flags (`--debug-timing`, `--diagnostics`)
- `std::time::Instant` -- for timing (no external crate needed)
