# Cross-Cutting — Remaining Work (Docs, CLI, Test-Suite, Observability, Config)

> **Parent:** `plans/p2-remaining-work.md` § E (Cross-cutting)
> **Status:** Multiple items across docs, CLI, test-suite, observability, and config. Estimated ~5–7 days total.
> **Estimated effort:** ~5–7 days total
> **See also:** Individual plans at `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md`, `02-perf-detectors-remaining.md`, `03-bad-practices-remaining.md`, `04-cache-incremental-remaining.md`

---

## Overview

This plan consolidates all cross-cutting items that don't fit neatly into a single P2.x workstream. These span documentation gaps, missing CLI flags, test-suite hygiene, observability improvements, configuration/schema completeness, and reporting gaps.

**Situation:** 7 documentation files exist, 3 major docs are missing. CLI has ~35 flags implemented; 3 are missing (taint-related + --diagnostics-summary). 77 test files exist but lack real-project fixtures and a benchmark CI gate. Reporting has text/JSON/SARIF but no HTML reporter.

---

## Executive Summary

- **Documentation**: 3 docs missing (`taint.md`, `bad-practices.md`, `perf-rules.md`). Estimated 1 day each.
- **CLI**: `--taint`, `--no-taint`, `--taint-show-paths`, `--diagnostics-summary` missing. Effort: ~1 day.
- **Test-suite**: Real-project smoke fixture, benchmark CI gate, BP negative fixtures. Effort: ~2 days.
- **Observability**: Per-detector timing on cache hit. Effort: ~1 day.
- **Config/Schema**: Missing fields (`evict_target_ratio`, `max_file_size_mb`, `bad_practices.severity_overrides`). Effort: ~1 day.
- **Reporting**: HTML reporter explicitly deferred (major feature, not in scope).

**Recommended order:** CLI flags (enables taint usage) → Documentation (enables user adoption) → Test-suite hygiene (enables quality confidence) → Observability (enables debugging) → Config/Schema (polish).

---

## Phase 1 — Documentation (3 docs)

> **Status:** ❌ Not started. All 3 are planned but not written.
> **Effort:** 3 days total

### 1.1 `docs/taint.md`

> Also tracked in `01-taint-tracking-remaining.md` Phase E 3.3.

- [x] Create `docs/taint.md` covering:
  - Overview: what taint tracking is (intra-procedural data-flow analysis)
  - Which CWE rules use it: CWE-22, CWE-78, CWE-79, CWE-89
  - Enabling: via `[slopguard.taint] enabled = true` in config, or `--taint` CLI flag
  - Model: 5 source kinds (UserInput, Args, EnvVar, File, Network), 6 sink kinds, 6 sanitizer kinds
  - Limitations: intra-procedural only, single-assignment-per-scope, no struct-field tracking
  - Reading output: `evidence.taint_path` in JSON output (source → hops → sink)
  - Custom sanitizers: name-based heuristic detection (`sanitize*`, `clean*`, etc.)
  - Performance: extraction always performed, graph-building lazy
- [x] Add reference from `README.md` to `docs/taint.md`

### 1.2 `docs/bad-practices.md`

> Also tracked in `03-bad-practices-remaining.md` (documentation section).

- [x] Create `docs/bad-practices.md` covering:
  - Overview: what Bad Practices detection catches (beyond CWE/PERF)
  - Per-rule index: one paragraph per BP rule with rationale and canonical fix
  - Source: adapted from `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md`
  - Include all 13 MVP rules (BP-1..BP-11, BP-13, BP-15)
  - For each: rule ID, title, brief description, fix example (code snippet), severity
  - Category grouping: Error Handling, Concurrency/Sync, Loops, Panics
  - How to enable/disable: `--no-bp`, `--bp-only`, `[bad_practices]` config block
- [x] Update with each new phase (BP-16..BP-25, BP-26..BP-45, BP-46..BP-65) as they ship
- [x] Add reference from `README.md` to `docs/bad-practices.md`

### 1.3 `docs/perf-rules.md`

> Also tracked in `02-perf-detectors-remaining.md` (plan mentions this as B.3).

- [x] Create `docs/perf-rules.md` covering:
  - Overview: what PERF rules detect (performance anti-patterns)
  - Per-rule index: one paragraph per shipped PERF rule with fix suggestion and example
  - Source: the current `--explain` output and `golang.json` `detection_notes` fields
  - Include all 160 shipped rules (PERF-1..100 + PERF-101..212 shipped so far)
  - For each: rule ID, title, brief description, fix example (code snippet), detection notes
  - Domain grouping: loop allocations, parsing, request path, Gin framework, data access, protocols, general performance
  - How to enable/disable: `--only PERF-*`, `--skip PERF-*`, `--rule-category performance`
- [x] Update with each new PERF batch as rules ship
- [x] Add reference from `README.md` to `docs/perf-rules.md`

---

## Phase 2 — CLI Flags (4 missing flags)

> **Status:** ❌ Not started
> **Effort:** 1 day

### 2.1 Taint-related CLI flags

> Also tracked in `01-taint-tracking-remaining.md` Phase E 3.1.

- [x] `--taint` flag: shorthand to enable taint tracking.
  - File: `src/cli/args.rs`
  - Wiring: `src/cli/args_impl.rs::scan_context()` — sets `ctx.taint_enabled = true`
  - Precedence: CLI `--taint` overrides config `[slopguard.taint] enabled = false`
- [x] `--no-taint` flag: disable taint tracking even if config enables it.
  - Precedence: `--no-taint` overrides both config and `--taint`
- [x] `--taint-show-paths` flag: include taint propagation paths in evidence output.
  - Sets `ctx.taint_show_paths = true`
  - Consumption: wire into JSON reporter (`src/reporting/json/entry.rs`) and SARIF reporter (`src/reporting/sarif/entry.rs`)
  - Text reporter: print path when flag is set

### 2.2 `--diagnostics-summary` flag

- [x] Add `--diagnostics-summary` CLI flag (no argument, unlike `--diagnostics <FILE>`)
  - Output (to stdout): single line with `Files: N, Cache hits: N, Cache misses: N, Cache hit rate: XX%, Slowest detector: NAME (Nms), Total time: Nms`
  - Source data: `ScanStats` from `src/engine/stats/scan.rs` (has `cache_hits`, `cache_misses`, `files_scanned`, `timing`)
  - Implementation: after scan completes, before exit, print the summary if the flag is set
  - Example output: `📊 Scan summary: 152 files, 89 cache hits / 10 misses (89.9%), slowest detector: CWE-089 (12.3ms), total 1.24s`
- [x] Ensure it works with both `scan` and `--list-rules` subcommands
- [x] Add to `--help` output

### 2.3 Update `CHANGELOG.md`

- [x] Add entries for new CLI flags under Unreleased section

---

## Phase 3 — Test-Suite Hygiene

> **Status:** ⏳ Partially done. 4 items remain.
> **Effort:** 2 days

### 3.1 Real-project PERF positive smoke fixture

- [x] Create `tests/fixtures/go/perf_real_world/` directory
- [x] Create `main.go` with a realistic HTTP server (or similar) that contains at least 3 patterns that fire shipped PERF detectors:
  - Example: `http.ListenAndServe` without timeouts → PERF-120
  - Example: `fmt.Sprintf` in hot path → PERF-150
  - Example: `time.After` in loop → matches an existing BP or PERF rule
- [x] Create `safe_main.go` with the idiomatic fixes — verify no findings
- [x] Add integration test: `perf_real_world_fixtures_fire_on_non_synthetic_code` in `tests/go_perf_detector_integration.rs`
- [x] Register in `tests/fixtures/manifest.toml`

### 3.2 Non-trivial clean Go file verification

- [x] Pick or create a clean Go file (~50–100 lines) that uses stdlib correctly:
  - HTTP handler with timeouts, proper error handling, correct sync patterns
  - Slice operations, string building, context usage
- [x] Run all shipped PERF + BP + CWE detectors against it
- [x] Verify zero false positives
- [x] Add as `tests/fixtures/go/perf_real_world/clean_go_file.txt`
- [x] Register in manifest with `required_rules = []`

### 3.3 Incremental benchmark CI gate

> Also tracked in `04-cache-incremental-remaining.md` (observability section).

- [x] Add `cargo bench --bench incremental_scan` to `.github/workflows/ci.yml`
- [x] Create `scripts/check_incremental_bench_budget.sh` (analogous to `check_bench_budget.sh`):
  - Parse `incremental_cold` and `incremental_warm` times from bench output
  - Assert warm is at least 5× faster than cold (not 10×, allowing for baseline overhead)
  - Threshold configurable via environment variable
- [x] Add to CI bench job after the existing `scan_throughput` bench
- [x] Document in `benchmarks.md`

### 3.4 BP negative fixtures

> Also tracked in `03-bad-practices-remaining.md` Phase 1.4.

- [x] Create negative fixtures for all 13 MVP BP rules (see `03-bad-practices-remaining.md` for detailed list) — safe fixtures exist for all 13 MVP rules
- [x] Register in `tests/fixtures/manifest.toml` — all 13 pairs registered

---

## Phase 4 — Observability

> **Status:** ❌ Not started
> **Effort:** 1 day

### 4.1 Per-detector timing on cache hit path

- [~] Currently per-detector timing is emitted only for files that get parsed and scanned. On a cache hit, the saved time is not measured.
- [~] Add a `TimingSpan` for the cache-hit path that records:
  - File read time (for hash check)
  - Filter-cached-findings time (`ctx.allows()` re-application)
  - Inline-ignore re-application time (if any)
  - The original parse+detect time that was **saved** (from the cache entry's `cached_at` or a new `original_detect_duration` field)
- [~] Emit these in `--diagnostics` output and `--debug-timing` output
- [~] New field in `CacheEntry`: `original_detect_duration_ms: u64` (populated at cache write time)
- [~] Show in `--diagnostics-summary`: "Cache hit saved: Nms total"

### 4.2 `CacheStore::evict_to_size` logging

> Also tracked in `04-cache-incremental-remaining.md` Phase 2.1.

### 4.3 `cache_hits` / `cache_misses` in `--diagnostics-summary`

- [x] `--diagnostics-summary` lands (Phase 2.2) and includes cache hit/miss counts

---

## Phase 5 — Config / Schema

> **Status:** ⏳ Partially done. 3 config fields missing.
> **Effort:** 1 day

### 5.1 Schema adds

- [x] `cache.evict_target_ratio`: float (0.0–1.0, default 0.9) in `slopguard.schema.json`
  - Also tracked in `04-cache-incremental-remaining.md` Phase 1.1
- [x] `cache.max_file_size_mb`: integer (default 4) in `slopguard.schema.json`
  - Also tracked in `04-cache-incremental-remaining.md` Phase 1.2
- [x] `bad_practices.severity_overrides`: map of rule ID → severity string in `slopguard.schema.json`
  - Also tracked in `03-bad-practices-remaining.md` Phase 1 (MVP hygiene)

### 5.2 Config struct updates

- [x] Add fields to `CacheConfig` in `src/engine/config/types.rs` (evict_target_ratio, max_file_size_mb)
- [~] Add `severity_overrides: Option<HashMap<String, Severity>>` to `BadPracticesConfig` — only `enabled` + `severity` exist in `BadPracticesConfig`; `severity_overrides` is in schema/template but not in Rust struct
- [~] Wire into `ScanContext.apply_finding_overrides()` for BP rules

### 5.3 Template updates

- [x] Add commented-out `[slopguard.taint]` block to `templates/slopguard.toml`:
  ```toml
  # [slopguard.taint]
  # enabled = false
  # show_paths = false
  ```
- [x] Add commented-out `[slopguard.bad_practices]` with `severity_overrides` example:
  ```toml
  # [slopguard.bad_practices]
  # enabled = true
  # severity = "medium"
  # severity_overrides = { "BP-5" = "high" }
  ```
- [x] Ensure cache config in template is up-to-date with `evict_target_ratio` and `max_file_size_mb` fields

---

## Phase 6 — Reporting

> **Status:** ⏳ HTML reporter explicitly deferred. No action planned.
> **Effort:** N/A (deferred)

### 6.1 HTML reporter

- [~] The HTML reporter is explicitly deferred in the plan (`plans/p2-remaining-work.md` C.3):
  > "deferred until the HTML reporter is added at all; today only text/JSON/SARIF exist."
- [~] Action: no work planned `(deferred → see plans/v3.0.0/)`

---

## Quick reference

| Phase | Items | Effort | Status | Blocked by |
|-------|-------|--------|--------|------------|
| 1 — Documentation | 3 docs (taint, bp, perf) | 3d | ❌ | CLI flags for taint (Phase 2) |
| 2 — CLI | 4 flags (taint ×3, diagnostics-summary) | 1d | ❌ | — |
| 3 — Test-suite | 4 items (smoke, clean, CI gate, negatives) | 2d | ⏳ | — |
| 4 — Observability | 2 items (timing, eviction logging) | 1d | ❌ | Cache infra (Phase 3) |
| 5 — Config/Schema | 3 fields + template updates | 1d | ⏳ | — |
| 6 — HTML reporter | Deferred | — | ⏳ | N/A |
