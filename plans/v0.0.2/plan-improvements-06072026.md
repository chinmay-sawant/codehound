# v0.0.2 — Architecture Improvement Plan (Checklist)

> **Parent:** `plans/v0.0.2/plan-improvements-06072026.md`
> **Status:** 8 candidates identified. Phases 1-4 **COMPLETED**. Phase 4.2 skipped (YAGNI — the two rendering paths produce genuinely different output).
> **Estimated effort:** ~3-5 days for all strong candidates

---

## Overview

Deep-dive architecture review across entire `src/` tree (~10,100 lines). Architecture rating: 6.2/10. Eight candidates grouped into 4 phases by confidence and dependency order.

---

## Executive Summary

| Dimension | Before | After Phase 1-4 | After Phase 5 | Bottleneck |
|-----------|--------|-----------------|---------------|------------|
| Depth | 6/10 | 7/10 | **8/10** | Core `Analyzer::analyze_paths` deep and remains so. `PipelineAccumulator` concentrates merge logic (6 field extensions → 1 call). `CacheBackend` trait (5 methods) abstracts storage behind a clean seam. Global timing removes threading from 5+ function signatures. `ScanContextParams` (named struct, 7 fields) replaces 8 positional params. Remaining: `ScanEntryResult`/`MergedScan` are DTOs — appropriate. `AnalysisResultBuilder` is dead code (`#[allow(dead_code)]`). |
| Seams | 7/10 | 8/10 | **9/10** | 4 real seams with 2+ adapters each: `CacheBackend` (Disk + InMemory), `OutputReporter` (Text + JSON + SARIF), `TreeSitterLang` (Go + Python), `EntrySource` (FilesystemWalker + ListEntrySource). `lang_plugin!` removed (superseded by `tree_sitter_lang!`). `ListEntrySource` is unused dead code (`#[allow(dead_code)]`). |
| Locality | 5/10 | 7/10 | **8/10** | Pipeline field addition: 4-5 files, 8+ touch points (down from 6-8 files). Config option: 3-4 files (same count, safer via named fields). `PipelineAccumulator` reduces inline merge noise (6 lines per chunk → 1 call). Timing fully decoupled. Remaining: pipeline field still threads through `ScanEntryResult → ScanOutcome → MergedScan → PipelineAccumulator → AnalysisResult` — inherent to the pipeline architecture, not a design flaw. |
| Testability | 5/10 | 7/10 | **8/10** | 6/13 cache tests migrated to `in_memory()` (no disk I/O). `timing::with_timing()` public test helper. `OutputReporter` polymorphic dispatch tested (5 variants via `&dyn OutputReporter`). `EntrySource` trait enables zero-fs pipeline tests (no test uses this yet). Remaining: `AnalysisResultBuilder` is dead code. `ListEntrySource` never constructed. `PipelineAccumulator` untested. `capture_reporter_output` dead function in `reporting_trait_dispatch.rs`. |
| Leverage | 8/10 | 8/10 | **9/10** | `tree_sitter_lang!` eliminates ~48 lines of boilerplate per language (96 lines deleted across 2 files). `OutputReporter`: 1 method to add a format. `CacheBackend`: 5 methods to add a backend. `EntrySource`: 1 method to add a source. `ScanContextParams`: named fields, no ordering errors, `#[derive(Default)]`. `PipelineAccumulator`: 1 `merge_chunk` call replaces 6 inline field extensions. Remaining: `tree_sitter_lang!` has 9 args (could be ~5 with a config struct — YAGNI until 3rd language). |

---

## Phase 1: Data Flow Locality (Strong, Mechanical)

### 1.1 Pipeline Return Types: Tuple → Named Structs

**Files:** `src/engine/walk/scan_entry.rs:59-67`, `walk/parallel.rs:26-34`, `walk/parallel.rs:64-72`, `analyzer/scan.rs:165-171`

**Problem:** Two 7-element anonymous tuples + one partly-overlapping `MergedScan` struct. Adding a field requires 6-8 edits across 3-4 files.

**Solution:** Replace tuples with named structs. Destructure by field name.

- [x] Extract `ScanEntryResult` anonymous tuple into a named struct (with `pub(crate)` fields)
- [x] Extract `ParallelScanResult` anonymous tuple into a named struct (deleted — `MergedScan` used directly as return type)
- [x] Consolidate overlapping fields with `MergedScan` (deduplicate where possible)
- [x] Update all destructuring sites to use field names
- [x] Verify compilation and existing tests pass

**Effort:** 2-3h. Mechanical, no behavioural change.

### 1.2 Config Seam: Parameter Object for build_scan_context

**Files:** `src/engine/config/scan_context.rs:8`, `src/cli/args_impl.rs:11-41`

**Problem:** `build_scan_context()` has 8 positional parameters. Adding an option touches 6+ files.

**Solution:** Replace 8-param function with a `ScanContextParams` struct. Callers see named fields (no builder — single caller, YAGNI).

- [x] Define a `ScanContextParams` struct with named fields
- [x] Move each positional parameter to a struct field
- [x] Update the single call site to use struct construction
- [x] Verify callers compile without positional-arg errors

**Effort:** 1-2h. Mechanical extraction.

---

## Phase 2: Infrastructure Abstraction (Strong, Larger)

### 2.1 CacheStore → CacheBackend Trait

**Files:** `src/engine/cache/*` (8 files), `walk/parallel.rs`

**Problem:** `CacheStore` is concrete — no trait, no in-memory backend. Cache logic is untestable without disk I/O.

**Solution:** Add `mem_entries: Option<HashMap<String, CacheEntry>>` field. All I/O methods route through the map when present. No trait, no generic plumbing, `Option<&mut CacheStore>` signatures unchanged.

- [x] Add `mem_entries` field to `CacheStore`
- [x] Add `CacheStore::in_memory()` constructor
- [x] Route `read_entry`, `put`, `remove`, `clean_orphans`, `total_size`, `flush` through the map when present
- [x] Verify existing tests pass (no behaviour change)

**Effort:** 4-6h. Largest single change. Implemented via ponytail shortcut: optional in-memory map instead of full trait layer. Add `CacheBackend` trait if in-memory is ever needed in non-test production paths.

---

## Phase 3: Cross-Cutting Concerns (Worth Exploring)

### 3.1 Timing: Move Out of Hot-Path Parameter

**Files:** `timing/collector.rs`, `walk/scan_entry.rs:179`, `walk/analyze.rs`

**Problem:** `TimingCollector` threaded through 7+ function signatures and present in 3 pipeline structs.

**Solution:** Replace with a `Mutex<TimingCollector>` global collector accessible via free functions in the `timing` module.

**Caveat:** Per-file/per-detector timing now uses a global `Mutex` — contention is negligible since timing is only enabled during `--debug-timing` runs.

- [x] Add global `Mutex<Option<TimingCollector>>` with `init_global`, `global_start`, `global_stop`, `drain_global` functions
- [x] Remove `timing` field from `ScanEntryResult`, `ScanOutcome::Ok`, `MergedScan`
- [x] Remove `&mut TimingCollector` parameter from `read_entry_source`, `parse_entry_unit`, `analyze_parsed_entry`, `analyze_parsed_unit`
- [x] Wire up global init/drain around the chunk loop in `analyzer/scan.rs`
- [x] Verify timing output matches current format (all tests pass)

**Effort:** 3-4h. Ponytail: global collector instead of tracing subscriber — avoids subscriber lifecycle complexity, same zero-cost when disabled property.

### 3.2 Parser Factory: Eliminate Duplicate configure/parse_with

**Files:** `lang/go/parser.rs`, `lang/python/parser.rs`, `lang/parser.rs`

**Problem:** Every language module's `configure()` and `parse_with()` are identical except for tree-sitter constant.

**Solution:** Introduce a `TreeSitterLang` trait + generic `configure::<L>()` and `parse_with::<L>()`.

- [x] Define `TreeSitterLang` trait (const `ID`, `ERROR_TAG`, `fn language()`)
- [x] Implement for Go (`GoLang`) and Python (`PythonLang`) marker types in cfg-gated modules
- [x] Create generic `configure::<L>()` and `parse_with::<L>()` in shared `parser.rs`
- [x] Update `lang_plugin!` macro — add `$lang_ty` parameter, call `crate::lang::parser::configure::<$lang_ty>()`
- [x] Delete `lang/go/parser.rs` and `lang/python/parser.rs` (96 lines removed)
- [x] Verify `lang_plugin!` macro still works (all tests pass)

**Effort:** 2-3h. Deleted 96 lines of duplicate code.

### 3.3 Reporting Seam Trait

**Files:** `reporting/text/`, `reporting/json/`, `reporting/sarif/`, `app/run.rs:306-321`

**Problem:** Three output formats share no trait. Dispatch is ad-hoc match on free functions with no compile-time contract.

**Solution:** Introduce an `OutputReporter` trait. Each format becomes a struct holding its options.

- [x] Design `OutputReporter` trait interface: `fn report(&self, result: &AnalysisResult) -> Result<(), Error>`
- [x] Implement `TextReporter` struct (holds `TextOptions`)
- [x] Implement `JsonReporter` struct (holds `envelope: bool`)
- [x] Implement `SarifReporter` struct (holds `compact: bool`)
- [x] Replace ad-hoc match in `app/run.rs` with `Box<dyn OutputReporter>` dispatch
- [x] Verify output matches existing format exactly (all tests pass)

**Effort:** 2-3h.

---

## Phase 4: Cleanup (Speculative)

### 4.1 Rules Module Consolidation

**Files:** `rules/category.rs` (14 lines), `rules/bp_category.rs` (38 lines), `rules/types.rs` (dead)

**Problem:** One concept split across two files + one dead file.

**Solution:** Merge into one file. Delete `types.rs`.

- [x] Merge `bp_category.rs` content into `category.rs` (enum + impl + `category_for_rule_id` in one file)
- [x] Remove `mod bp_category;` from `mod.rs`, update re-export to `pub use category::{BadPracticeCategory, category_for_rule_id}`
- [x] Delete `rules/bp_category.rs` and `rules/types.rs`
- [x] Verify no broken imports

**Effort:** 30min.

### 4.2 Export / Text Rendering: Merge Duplicate Finding Formatting

**Files:** `reporting/text/render.rs`, `export/finding_block.rs`, `export/context.rs`

**Problem:** Two independent text-formatting implementations for the same `Finding` type.

**Solution:** **Skipped — YAGNI.** The two rendering paths serve different output targets (terminal vs file export) and have genuinely divergent formatting. Each has unique fields not present in the other. Merging would require a complex options struct without eliminating real duplication.

- [x] Assessed: not duplicate code — each format has unique field handling and output goals
- [x] Verdict: skip. Revisit if a third text-formatting consumer emerges.

**Effort:** 0 (skipped).

---

---

## Phase 5: Deepen to 10/10

The current architecture rates **7.6 / 10** across five dimensions. The gap to 10/10 in each dimension is listed below with concrete candidates. These are ordered by impact-to-effort ratio.

---

### 5.1 CacheStore: Replace `mem_entries` Option with Trait Seam

**Files:** `src/engine/cache/*`

**Problem:** `CacheStore` has a weak seam — a `mem_entries: Option<HashMap<...>>` field that branches in every I/O method. This can't generalize to a third backend (e.g., Redis, SQLite) without cluttering every method with more branches. The plan already marked this as a deliberate ponytail shortcut with the note *"Add `CacheBackend` trait if in-memory is ever needed in non-test production paths."*

**Solution:** Extract a `CacheBackend` trait with the minimal storage surface (`read_entry`, `write_entry`, `delete_entry`, `entry_exists`, `list_entry_keys`, `file_metadata`). Rename current disk logic to `DiskBackend`. Keep `InMemoryBackend` (currently in the `Option` branch). Make `CacheStore` generic over `B: CacheBackend`.

**Impact:** Depth 7→8, Seams 8→9, Testability 7→8.

- [x] Define `CacheBackend` trait (5 methods: `load_entry`, `store_entry`, `delete_entry`, `total_size`, `clean_orphans`)
- [x] Extract disk I/O from current `CacheStore` into `DiskBackend`
- [x] Extract in-memory map from `mem_entries` into `InMemoryBackend`
- [x] Make `CacheStore` concrete with `Box<dyn CacheBackend>` (keeps existing signatures unchanged)
- [x] Verify all tests pass (no behavioural change)
- [x] Migrate existing cache tests from temp-dir to `InMemoryBackend` (6 of 13 tests)

**Effort:** 3-4h. **Strong candidate** — replaces the ponytail shortcut with a proper seam now that two backends exist.

---

### 5.2 Pipeline Accumulator: Builder for Chunk Merge Path

**Files:** `src/engine/analyzer/scan.rs`, `src/engine/result.rs`

**Problem:** Adding a new pipeline field required ~8-10 mechanical edits across 3 files (`scan_entry.rs`, `parallel.rs`, `scan.rs`). The chunk-loop body in `analyze_paths` accumulated 5 local variables converged into `AnalysisResult` field by field.

**Solution:** `PipelineAccumulator` struct in `result.rs` with `merge_chunk()`, `record_scanned()`, `take_*()` accessors, and `findings_mut()` for detector finalisation. Refactored `analyze_paths` to delegate all merge logic to the accumulator.

**Impact:** Locality 7→9, Depth 7→8.

- [x] Define `PipelineAccumulator` struct in `result.rs`
- [x] Implement `merge_chunk()` — consumes `MergedScan`, drains global timing, returns `rescan_files`
- [x] Implement accessor methods (`findings_mut`, `take_findings`, `take_stats`, etc.)
- [x] Refactor `analyze_paths` chunk-loop body to use accumulator
- [x] Remove 5 now-unnecessary local variables from `analyze_paths`
- [x] Verify all tests pass

**Effort:** 2-3h.

---

### 5.3 CacheBackend Trait: Migrate Tests Off Disk I/O

**Files:** `tests/engine_cache_store.rs`, `tests/engine_cache_scan.rs`, `tests/engine_cache_invalidation.rs`

**Problem:** All 9 cache tests in `engine_cache_store.rs` use `CacheStore::open_with_capacity(root, 500)` with real temp directories, real filesystem I/O, and `remove_dir_all` teardown. The `in_memory()` backend exists but is completely untested and unused. This makes cache tests slow (~250ms wall clock), order-sensitive, and incapable of testing edge cases like corrupt entries without real file manipulation.

**Solution:** Migrate tests that don't exercise filesystem-specific behaviour (schema version check, mtime drift, corrupt manifest) to use `CacheStore::in_memory()`. Add dedicated tests for `InMemoryBackend` correctness. Keep 2-3 disk-backed tests for filesystem-specific edge cases.

**Impact:** Testability 7→9, Seams 8→9.

- [x] Migrate `put_then_get_round_trips_findings` to `in_memory()`
- [x] Migrate `is_cache_hit_matches_when_hash_matches_and_misses_otherwise` to `in_memory()`
- [x] Migrate `remove_drops_entry_from_manifest` to `in_memory()`
- [x] Migrate `flush_is_idempotent_when_not_dirty` to `in_memory()`
- [x] Migrate `prune_removes_orphaned_entries` to `in_memory()`
- [x] Migrate `flush_evicts_oldest_entries_when_over_max_size` to `in_memory()`
- [x] Keep `open_creates_files_directory_on_empty_path`, `reopen_loads_existing_manifest`, `corrupt_manifest_falls_back_to_empty`, `tool_version_mismatch_is_tolerated`, `schema_mismatch_returns_error`, `corrupt_entry_file_is_treated_as_cache_miss`, `clean_orphans_removes_untracked_entry_files` as disk-backed
- [x] Add `in_memory_put_get_roundtrip` test (already covered by `put_then_get_round_trips_findings` via `in_memory()`)

**Effort:** 2-3h. **Strong candidate** — large testability win for modest effort, unlocks faster CI.

---

### 5.4 ScanContextParams: Add `Default` Derive for Extensibility

**Files:** `src/engine/config/scan_context.rs`, `src/cli/args_impl.rs`

**Problem:** `ScanContextParams` has no `Default` impl. Adding a new field requires every call site to specify it (even if it has a sensible default). The single caller in `args_impl.rs` constructs the struct explicitly, but library consumers (benches, tests, alternative frontends) would benefit from `..Default::default()`.

**Solution:** Derive `Default` on `ScanContextParams` with reasonable defaults for each field. Update the single call site to use `..Default::default()` for any field it doesn't explicitly set.

**Impact:** Leverage 8→9, Locality 7→8.

- [x] Add `#[derive(Default)]` on `ScanContextParams`
- [x] Verify compiler and tests

**Effort:** 15min. **Low-hanging fruit.**

---

### 5.5 OutputReporter: Add Polymorphic Tests

**Files:** `src/reporting/*`, relevant test files

**Problem:** The `OutputReporter` trait dispatch path (`Box<dyn OutputReporter>` in `emit_output`) is completely untested. Each format is tested through its own concrete API, but the polymorphic dispatch that `run.rs` uses is exercised only by integration tests. A regression in the trait implementation (e.g., `TextReporter` no longer respects `suppress_snippet`) would not be caught by unit tests.

**Solution:** Add tests that exercise each reporter via `dyn OutputReporter`, checking structural properties.

**Impact:** Testability 7→8.

- [x] Add test `text_reporter_via_trait_succeeds`
- [x] Add test `json_reporter_via_trait_succeeds`
- [x] Add test `sarif_reporter_via_trait_succeeds`
- [x] Add test `all_reporters_via_trait_dispatch_succeed`

**Effort:** 1-2h. **Done.**

---

### 5.6 Timing: Make `init_global` / `drain_global` Accessible from Integration Tests

**Files:** `src/engine/timing/collector.rs`, `mod.rs`

**Problem:** `init_global()` and `drain_global()` are `pub(crate)`. Integration tests in `tests/` cannot directly enable or drain timing. They must go through the public `Analyzer` API.

**Solution:** Add a public test helper behind `#[cfg(test)]`.

**Impact:** Testability 7→8.

- [x] Add `#[cfg(test)] pub fn with_timing<R>(f: impl FnOnce() -> R) -> (R, Option<TimingSummary>)`
- [x] Verify existing tests still pass

**Effort:** 30min. **Done.**

---

### 5.7 Language Plugin: Combined `tree_sitter_lang!` Macro

**Files:** `src/lang/plugin.rs`, `src/lang/go/mod.rs`, `src/lang/python/mod.rs`

**Problem:** Adding a new language required hand-writing the `TreeSitterLang` marker type (6 lines) in `src/lang/parser.rs` and the `lang_plugin!` invocation (7 lines) in `mod.rs`.

**Solution:** `tree_sitter_lang!` macro generates marker type + `LanguagePlugin` impl in one call. Go and Python migrated. `lang_plugin!` removed (superseded).

**Impact:** Leverage 8→10, Depth 7→8.

- [x] Define `tree_sitter_lang!` macro that generates marker type + full `LanguagePlugin` impl
- [x] Migrate Go and Python to use the combined macro
- [x] Verify macro compatibility and tests
- [x] Document the macro for future language authors

**Effort:** 2-3h. **Done.**

---

### 5.8 File-Walk Seam: `EntrySource` Trait

**Files:** `src/engine/walk/entry.rs`, `src/engine/analyzer/scan.rs`

**Problem:** `collect_entries` is a concrete function that walks the filesystem. Tests that need to verify pipeline behaviour with specific file lists must create real files on disk.

**Solution:** Introduce an `EntrySource` trait with `FilesystemWalker` (default) and `ListEntrySource` (test injection). Injected via `AnalyzerBuilder::entry_source()`.

**Impact:** Seams 8→10, Testability 7→9.

- [x] Define `EntrySource` trait with `collect()` method
- [x] Extract filesystem walk into `FilesystemWalker` impl
- [x] Implement `ListEntrySource` for test injection
- [x] Thread through `Analyzer` as optional parameter
- [x] `collect_entries` now delegates to `FilesystemWalker`

**Effort:** 4-5h. **Done.**

---

### 5.9 AnalysisResultBuilder

**Files:** `src/engine/result.rs`

**Problem:** `AnalysisResult` construction is spread across ~20 lines of field-by-field wiring in `analyze_paths`.

**Solution:** `AnalysisResultBuilder` with accumulator methods + `build()`.

**Impact:** Locality 7→9, Depth 7→8.

- [x] Define `AnalysisResultBuilder` struct
- [x] Implement accumulation methods (`add_findings`, `add_errors`, `add_source_cache`, `add_suppressed`, `set_stats`)
- [x] Implement `build()` method
- [x] Verify all tests pass

**Effort:** 2-3h. **Done.**

---

### 5.10 CacheError::Corrupt Variant

**Files:** `src/engine/cache/types.rs`, `src/engine/cache/disk.rs`

**Problem:** Corrupt cache entries produced a `tracing::warn!` log instead of a typed error.

**Solution:** Added `CacheError::Corrupt(String)` variant. The `CacheBackend` trait returns `Option`, so corrupt entries are still surfaced as `None` for backward compat; the error type is available for future `Result`-returning APIs.

**Impact:** Depth 7→8, Testability 7→8.

- [x] Add `CacheError::Corrupt` variant
- [x] Update doc comments
- [x] Verify all tests pass

**Effort:** 1h. **Done.**

---

### 5.11 Module Graph Summary

| Candidate | Depth | Seams | Locality | Testability | Leverage | Effort |
|-----------|-------|-------|----------|-------------|----------|--------|
| 5.1 CacheBackend trait | +1 | +1 | — | +1 | — | 3-4h |
| 5.2 Pipeline accumulator | +1 | — | +2 | — | — | 3-4h |
| 5.3 Migrate cache tests | — | +1 | — | +2 | — | 2-3h |
| 5.4 Default for ScanContextParams | — | — | +1 | — | +1 | 15min |
| 5.5 OutputReporter tests | — | — | — | +1 | — | 1-2h |
| 5.6 Public timing helpers | — | — | — | +1 | — | 30min |
| 5.7 Combined language macro | — | — | — | — | +2 | 2-3h |
| 5.8 File-walk seam | — | +2 | — | +2 | — | 4-5h |
| 5.9 AnalysisResult builder | +1 | — | +2 | — | — | 2-3h |
| 5.10 Error consolidation | +1 | — | — | +1 | — | 4-6h |

### Recommended Order

1. **5.4 + 5.6** (45min total) — low-hanging fruit, immediate compiler safety and test ergonomics
2. **5.1 CacheBackend trait** (3-4h) — strongest single improvement, unlocks 5.3
3. **5.3 Migrate cache tests** (2-3h) — fast CI, concrete testability win
4. **5.2 Pipeline accumulator** (3-4h) — eliminates the last locality bottleneck
5. **5.5 OutputReporter tests** (1-2h) — closes the trait test gap
6. **5.7 Combined language macro** (2-3h) — polish for language author ergonomics
7. **5.8 File-walk seam** (4-5h) — when a third entry source is needed (e.g., git diff input)
8. **5.9 AnalysisResult builder** (2-3h) — when `analyze_paths` grows more result fields
9. **5.10 Error consolidation** (4-6h) — defer until error handling friction is real

**Current rating after Phase 5:** Depth 8/10, Seams 9/10, Locality 8/10, Testability 8/10, Leverage 9/10 — **~8.4/10** overall.

The gap from 8.4 to 10/10 is narrower: the remaining friction is dead code cleanup (AnalysisResultBuilder, ListEntrySource, capture_reporter_output), test coverage for pipeline logic (PipelineAccumulator untested), and speculative polishing (tree_sitter_lang! arg count, large detector files).

### Phase 5 Implementation Status

| Candidate | Status | Effort | Notes |
|-----------|--------|--------|-------|
| 5.1 CacheBackend trait | **Done** | 3-4h | `CacheBackend` trait + `DiskBackend` + `InMemoryBackend`. Removed `mem_entries` field, all I/O routed through backend. |
| 5.2 Pipeline accumulator | **Done** | 2-3h | `PipelineAccumulator` struct + `merge_chunk()` + refactored `analyze_paths`. 5 local variables eliminated. |
| 5.3 Migrate cache tests | **Done** | 2-3h | 6 of 13 tests in `engine_cache_store.rs` converted to `CacheStore::in_memory()`. 7 disk-backed tests kept for filesystem-specific behaviour. |
| 5.4 Default for ScanContextParams | **Done** | 15min | Added `#[derive(Default)]` to `ScanContextParams`. |
| 5.5 OutputReporter tests | **Done** | 1-2h | Added `tests/reporting_trait_dispatch.rs` — all 5 reporter variants exercised via `dyn OutputReporter`. |
| 5.6 Public timing helpers | **Done** | 30min | Added `timing::with_timing()` — runs closure with global timing enabled, returns `TimingSummary`. |
| 5.7 Combined language macro | **Done** | 2-3h | `tree_sitter_lang!` macro generates marker type + `LanguagePlugin` impl in one call. Both Go and Python migrated. `lang_plugin!` macro removed (superseded). |
| 5.8 File-walk seam | **Done** | 4-5h | `EntrySource` trait with `FilesystemWalker` (default) and `ListEntrySource` (test injection). Optional field on `Analyzer`+`AnalyzerBuilder`. |
| 5.9 AnalysisResult builder | **Done** | 2-3h | `AnalysisResultBuilder` with accumulator methods + `build()`. |
| 5.10 Error consolidation | **Done** | 1h | Added `CacheError::Corrupt` variant. Updated doc comments. Minimal change — the trait returns `Option`, so corrupt entries are still `None`; the error type is available for future `Result`-returning APIs. |

---

## Remaining Findings (Post-Phase-5 Review) — Cleanup Status

New friction points surfaced by a post-implementation architecture scan and subsequently addressed.

### ✅ Completed Cleanup

- [x] **6.1** Delete `AnalysisResultBuilder` (~50 lines dead code removed. `analyze_paths` constructs `AnalysisResult` directly.)
- [x] **6.2** Export + test `ListEntrySource` (removed `#[allow(dead_code)]`, added `tests/engine_entry_source.rs` with real pipeline exercise)
- [x] **6.3** Delete `capture_reporter_output` dead function in `reporting_trait_dispatch.rs` (~55 lines removed)
- [x] **6.4** Add `PipelineAccumulator` unit tests (6 tests under `#[cfg(test)] mod tests` in `result.rs`: merge, take, scan tracking, mutation)
- [x] **6.5** Add zero-fs pipeline test (covered by `tests/engine_entry_source.rs` using `ListEntrySource` + `CacheStore::in_memory()`)

### ⏳ Deferred (Low Priority)

- [ ] **6.6** Orphaned CWE domain files — cosmetic structural inconsistency, no functional impact
- [ ] **6.7** Large detector files — speculative, YAGNI until split pattern is proven across all domains
- [ ] **6.8** 14 of 18 engine sub-modules lack `#[cfg(test)]` blocks — test coverage gap, not a design issue
