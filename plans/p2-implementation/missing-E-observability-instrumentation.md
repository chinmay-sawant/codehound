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

- [ ] Create `src/engine/timing.rs`
- [ ] Define `TimingSpan`:
  ```rust
  pub struct TimingSpan {
      pub name: &'static str,
      pub start: Instant,
      pub duration: Option<Duration>,
  }
  ```
- [ ] Define `TimingCollector`:
  ```rust
  pub struct TimingCollector {
      spans: Vec<TimingSpan>,
      enabled: bool,
  }
  ```
- [ ] Methods on `TimingCollector`:
  - [ ] `new(enabled: bool) -> Self`
  - [ ] `start(&mut self, name: &'static str) -> usize` -- returns span index
  - [ ] `stop(&mut self, index: usize)` -- records duration
  - [ ] `measure<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T` -- convenience wrapper
  - [ ] `to_summary(&self) -> TimingSummary` -- aggregate statistics

### 1.2 Define `TimingSummary`

- [ ] `TimingSummary` struct:
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
- [ ] Serialize to JSON for machine-readable output

### 1.3 Instrument the major pipeline phases

- [ ] In `analyze_paths()` (`src/engine/analyzer.rs:70-97`):
  - [ ] Phase 1: `"file_walk"` -- `collect_entries()` duration
  - [ ] Phase 2: `"parse_and_detect"` -- `scan_entries_parallel()` duration
  - [ ] Phase 3: `"sort_results"` -- sorting findings duration
- [ ] In `scan_entries_parallel()` (`src/engine/walk.rs:284-335`):
  - [ ] Phase 2a: `"file_read"` -- cumulative time reading files from disk
  - [ ] Phase 2b: `"tree_sitter_parse"` -- cumulative time parsing with tree-sitter
  - [ ] Phase 2c: `"fact_extraction"` -- cumulative time extracting GoUnitFacts/GoPerfFacts
  - [ ] Phase 2d: `"detector_execution"` -- cumulative time running all detectors
- [ ] In `app.rs::run()`:
  - [ ] Phase 4: `"export"` -- exporting context/chunk files
  - [ ] Phase 5: `"reporting"` -- formatting and writing output
- [ ] In `app.rs::run()`:
  - [ ] Phase 0: `"config_load"` -- loading and merging configuration

### 1.4 Integration with tracing

- [ ] If `tracing` is already in use (`src/main.rs` line ~9 has `tracing_subscriber::fmt::init()`), respect its span system
- [ ] Option: Use `tracing::span` for development-mode diagnostics, `TimingCollector` for production-mode lightweight timing
- [ ] Decision: [ ] Use `TimingCollector` (lightweight, no tracing overhead when disabled) for the product feature; keep `tracing` for `RUST_LOG=trace` developer debugging

---

## Phase 2: Per-Rule / Per-Detector Timing (Debug Mode)

### 2.1 Add per-detector timing to `ScanContext`

- [ ] Add field to `ScanContext` in `src/core/scan.rs`:
  ```rust
  pub struct ScanContext {
      // ... existing fields ...
      pub debug_timing: bool,  // enabled via --debug-timing flag
  }
  ```

### 2.2 Instrument detector execution

- [ ] In `GoCweScan::run()` (`src/lang/go/detectors/cwe/mod.rs:47-57`):
  - [ ] If `ctx.debug_timing`, wrap each rule function call with timing:
    - [ ] Before calling `detect_cwe_N()`: record start time
    - [ ] After: record duration, accumulate per-rule
  - [ ] Store per-rule timings in a `HashMap<String, Duration>` on the detector
- [ ] Same for `GoPerfScan::run()` in `src/lang/go/detectors/perf/mod.rs`
- [ ] In `scan_entry()` (`walk.rs:135-197`):
  - [ ] Collect per-detector timings into a per-file `TimingCollector`
  - [ ] Aggregate into the global `TimingCollector` after all files processed

### 2.3 Output per-detector timing

- [ ] In text reporter (`src/reporting/text.rs`):
  - [ ] When `--debug-timing` is set, print a section after findings:
    ```
    --- Detector Timing (top 10) ---
    detect_cwe_89   :  1.23ms  (12.4%)
    detect_cwe_78   :  0.89ms  ( 8.9%)
    detect_cwe_22   :  0.76ms  ( 7.6%)
    ...
    Total detector time: 9.94ms across 175 rules
    ```
- [ ] In JSON reporter:
  - [ ] Add `"timing"` object with per-rule durations when `--debug-timing`
- [ ] In SARIF reporter:
  - [ ] Add timing data as `run.properties.slopguardTiming`

---

## Phase 3: Scan Statistics / Summary

### 3.1 Define `ScanStats` struct

- [ ] Create `src/engine/stats.rs`
- [ ] Define `ScanStats`:
  ```rust
  pub struct ScanStats {
      pub files_scanned: usize,
      pub files_skipped: usize,          // due to ignore/exclude rules
      pub files_errored: usize,
      pub files_cached: Option<usize>,   // when P2.3 is implemented
      pub bytes_scanned: u64,
      pub lines_scanned: u64,

      pub findings_total: usize,
      pub findings_by_severity: HashMap<Severity, usize>,
      pub findings_by_rule: Vec<(String, usize)>,  // top rules sorted by count
      pub findings_suppressed: Option<usize>,       // when P2.2 is implemented

      pub rules_executed: usize,
      pub detectors_loaded: usize,

      pub timing: Option<TimingSummary>,
  }
  ```
- [ ] Implement `ScanStats::from_result(result: &AnalysisResult) -> Self`
- [ ] Implement `ScanStats::merge(&mut self, other: &ScanStats)` for parallel aggregation

### 3.2 Collect statistics during scan

- [ ] In `collect_entries()` (`walk.rs:31-72`):
  - [ ] Count `files_skipped` (entries filtered out by ignore/glob/language)
- [ ] In `scan_entry()` (`walk.rs:135-197`):
  - [ ] Count file size in bytes and lines
  - [ ] Count findings per file
- [ ] In `scan_entries_parallel()` (`walk.rs:284-335`):
  - [ ] Aggregate per-file stats into global `ScanStats`
  - [ ] Count `files_errored`
- [ ] In `analyze_paths()`:
  - [ ] Build final `ScanStats` and attach to `AnalysisResult`
- [ ] Add `stats: Option<ScanStats>` field to `AnalysisResult` in `src/engine/result.rs`

### 3.3 Report statistics

- [ ] In text reporter (`src/reporting/text.rs`):
  - [ ] Extend the existing footer summary (already shows severity counts and top rules)
  - [ ] Add: files scanned/skipped/errored, timing summary
  - [ ] When `--verbose`: show full breakdown
  - [ ] Example:
    ```
    Scanned 1,284 files (342,156 lines) in 1.23s
    Skipped 56 files (ignored), 3 errors
    128 findings: 0 Critical, 2 High, 45 Medium, 81 Low
    Top rules: CWE-79 (15), PERF-1 (12), CWE-22 (8)
    ```
- [ ] In JSON reporter:
  - [ ] Add `"stats"` object to envelope output (`--json-envelope`)
  - [ ] NDJSON: add a stats record at the end? Or only in envelope mode. Decision: envelope only.
- [ ] In SARIF reporter:
  - [ ] Add stats to `run.properties.slopguardScanStats`

---

## Phase 4: Machine-Readable Diagnostics

### 4.1 JSON diagnostics mode

- [ ] Add `--diagnostics <FILE>` CLI flag:
  ```rust
  #[arg(long = "diagnostics", help = "Write machine-readable diagnostics JSON to FILE")]
  pub diagnostics_file: Option<PathBuf>,
  ```
- [ ] Format: JSON file containing:
  ```json
  {
    "tool": "slopguard",
    "version": "0.1.0",
    "timestamp": "2026-06-10T12:00:00Z",
    "scan": {
      "files_scanned": 1284,
      "files_skipped": 56,
      "files_errored": 3,
      "files_cached": 1200,
      "bytes_scanned": 12345678,
      "lines_scanned": 342156,
      "duration_ms": 1230
    },
    "findings": {
      "total": 128,
      "critical": 0,
      "high": 2,
      "medium": 45,
      "low": 81,
      "info": 0,
      "suppressed": 15
    },
    "timing": {
      "phases": [
        { "name": "config_load", "duration_ms": 5 },
        { "name": "file_walk", "duration_ms": 45 },
        { "name": "cache_check", "duration_ms": 30 },
        { "name": "parse_and_detect", "duration_ms": 1100 },
        { "name": "sort_results", "duration_ms": 10 },
        { "name": "export", "duration_ms": 15 },
        { "name": "reporting", "duration_ms": 25 }
      ]
    },
    "detectors": {
      "loaded": 275,
      "executed": 275,
      "top_by_time": [
        { "rule": "CWE-89", "duration_ms": 12.3 },
        { "rule": "CWE-78", "duration_ms": 8.9 }
      ]
    },
    "cache": {
      "hits": 1200,
      "misses": 84,
      "hit_rate": 0.934
    }
  }
  ```

### 4.2 Integration with CI/CD

- [ ] `--diagnostics` file can be consumed by CI pipelines:
  - [ ] Plot findings-over-time charts
  - [ ] Alert on scan time regressions
  - [ ] Track cache hit rate degradation
- [ ] Document the diagnostics schema in `docs/diagnostics.md`

---

## Phase 5: Keep Instrumentation Low-Overhead When Disabled

### 5.1 Zero-cost when off

- [ ] `TimingCollector::new(false)` creates a no-op collector:
  - [ ] `start()` returns a dummy index, does nothing
  - [ ] `stop()` is a no-op
  - [ ] `measure(f)` just calls `f()` without timing
- [ ] `ScanStats` collection: always collect file count and finding count (already tracked), add byte/line counts only when `--verbose` or `--diagnostics`
- [ ] Per-detector timing: completely disabled unless `--debug-timing` or `--diagnostics`

### 5.2 Benchmark

- [ ] Add benchmark: scan with instrumentation disabled (default) vs enabled (`--debug-timing`)
- [ ] Target: <1% overhead when disabled, <5% when enabled (only timing, no per-detector)

---

## Phase 6: Testing

### 6.1 Unit tests

- [ ] Create `tests/engine_timing.rs`
- [ ] Test `TimingCollector`:
  - [ ] `measure()` returns correct value and records duration
  - [ ] Multiple spans aggregated correctly
  - [ ] `to_summary()` computes correct totals and percentages
- [ ] Test no-op `TimingCollector`:
  - [ ] `measure()` returns correct value
  - [ ] No timing recorded

### 6.2 Integration tests

- [ ] Test `--diagnostics <file>` writes valid JSON
- [ ] Test diagnostics file contains expected top-level keys
- [ ] Test scan phase timings are non-zero
- [ ] Test `--debug-timing` prints detector timing in text output
- [ ] Test `--json-envelope` includes `stats` object
- [ ] Test default mode: no timing output (just findings + severity summary)

---

## Phase 7: Integration Points with Other P2 Features

### 7.1 With P2.3 (Incremental Analysis)

- [ ] `ScanStats.files_cached` -- populated by incremental analysis cache hits
- [ ] `diagnostics.cache` section -- hit rate, miss count
- [ ] Timing phases: add `"cache_check"` phase (checking manifest for cache hits)

### 7.2 With P2.2 (Baseline)

- [ ] `ScanStats.findings_suppressed` -- count of findings filtered by baseline
- [ ] Show suppressed count in summary output

### 7.3 With P2.1 (Taint Tracking)

- [ ] Timing phases: add `"taint_analysis"` phase when taint tracking is enabled
- [ ] Diagnostics: add taint-specific stats (paths found, sources identified, sinks matched)

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
