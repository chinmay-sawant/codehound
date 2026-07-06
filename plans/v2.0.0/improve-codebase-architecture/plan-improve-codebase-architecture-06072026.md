# v2.0.0 — Improve Codebase Architecture (Checklist)

> **Parent:** `plans/v2.0.0/plan-improvements-06072026.md` (Phases 1–5 completed)
> **Source:** 5-subagent architecture scan via `/improve-codebase-architecture` (2026-07-06)
> **Status:** **ALL PHASES COMPLETED** + push-to-10 follow-up (2026-07-06). Latest rating: **~8.8/10** (was 8.4 pre-plan).
> **Estimated effort:** ~2–4 days for Phases 1–3 (strong + worth exploring)

---

## Overview

Fresh architecture review across entire `src/` tree (~35,150 lines, 74 test files, 300 tests). Five parallel subagents rated Depth, Seams, Locality, Testability, and Leverage against live Rust code. Prior Phase 1–5 work confirmed — rating holds at **8.4/10**.

---

## Executive Summary

| Dimension | Current | Target (Phase 1–3) | Target (Phase 4–5) | Bottleneck |
|-----------|---------|--------------------|--------------------|------------|
| Depth | **8/10** | 8/10 | **9/10** | `Analyzer::analyze_paths`, detector bundles, cache layering are deep. Shallow: `OutputReporter` thin delegates, `ScanContextParams` pass-through, wide `CacheStore` public surface, `AnalyzerBuilder` 1:1 field mapping. |
| Seams | **9/10** | **10/10** | 10/10 | 6 real seams with 2+ adapters: `CacheBackend`, `OutputReporter`, `TreeSitterLang`, `EntrySource`, `LanguagePlugin`, `Detector`. Leakage: `collect_entries()` bypasses `EntrySource`; `no_terminal` bypasses `OutputReporter`; `Registry`/`CacheBackend` not injectable at app boundary. |
| Locality | **8/10** | **9/10** | 9/10 | `PipelineAccumulator` concentrates merge. Friction: `ScanOutcome` mirrors `ScanEntryResult` (~3 touch sites per field); config split across `ScanContextParams` + CLI patches + `PathFilters` + `CacheConfig`; finding fields duplicated 3× (wire/JSON/export). |
| Testability | **8/10** | **9/10** | 9/10 | Strong seam tests: cache in-memory, `OutputReporter` trait dispatch, `ListEntrySource`, `PipelineAccumulator` (6 tests). Gaps: `parallel.rs` (~400 lines, 0 direct tests), `with_timing()` dead, `app/run.rs` orchestration untested, cache integration tests still disk-heavy. |
| Leverage | **9/10** | 9/10 | **10/10** | `tree_sitter_lang!`, registry codegen (175 CWE + 221 PERF), trait leverage on cache/reporting/entry. Remaining: manual feature-gated plugin registration, 3 parallel build generators (`gen_cwe`/`gen_perf`/`gen_bp`). |

**Overall rating:** 8.4/10 → target **9.2/10** after Phases 1–3, **9.6/10** after Phases 4–5.

---

## Phase 1: Pipeline Locality (Strong, Mechanical)

### 1.1 Collapse ScanOutcome onto ScanEntryResult

**Files:** `src/engine/walk/parallel.rs`, `src/engine/walk/scan_entry.rs`

**Problem:** `ScanOutcome::Ok` duplicates every `ScanEntryResult` field. `dispatch_parallel_scan` destructures and repacks in `merge_parallel_results` — adding a per-file pipeline field touches ~3 sites.

**Solution:** Replace field-mirror enum variant with `Fresh(ScanEntryResult)` or embed shared struct; cache-hit variant carries only the delta.

**Impact:** Locality 8→9. Per-field pipeline edits drop from ~3 to ~2.

- [x] Redesign `ScanOutcome` enum: `Fresh(ScanEntryResult)`, `Cached { ... }`, `Err(ScanError)`
- [x] Remove duplicate field list from `ScanOutcome::Ok`
- [x] Update `dispatch_parallel_scan` to stop destructuring/repacking identical fields
- [x] Update `merge_parallel_results` to consume new shape
- [x] Verify all walk/parallel call sites compile
- [x] Verify existing tests pass (no behavioural change)

**Effort:** 2–3h. Mechanical, no behavioural change.

### 1.2 Use ScanStats::merge for Final Stats Assembly

**Files:** `src/engine/analyzer/scan.rs`, `src/engine/stats/scan.rs`, `src/engine/diagnostics/build.rs`

**Problem:** `analyze_paths` manually copies 8 `chunk_stats` fields line-by-line into `scan_stats`. New `ScanStats` fields are easy to miss here and in `ScanDiagnostics` wiring.

**Solution:** Reuse existing `ScanStats::merge()` for the final aggregation step instead of field-by-field assignment.

**Impact:** Locality 8→8.5. Reduces miss risk when extending stats.

- [x] Replace manual field copies in `analyzer/scan.rs` with `scan_stats.merge(&chunk_stats)`
- [x] Audit `diagnostics/build.rs` for parallel manual wiring
- [x] Verify stats output unchanged in integration tests
- [x] Verify `collect_stats` diagnostics JSON still correct

**Effort:** 1h. Mechanical.

---

## Phase 2: Seam Closure & Config Locality (Strong)

### 2.1 Unify Run-Time Config Construction

**Files:** `src/engine/config/scan_context.rs`, `src/app/run.rs`, `src/engine/config/discover.rs`

**Problem:** Config threads through 4 concepts — `ScanContextParams`, post-hoc CLI patches (`taint_*`, `bad_practices_*`, `show_ignored`, `bp_only`), separate `PathFilters` build, `CacheConfig`. Adding a TOML option touches 5–7 files; understanding scan flags requires 3 modules.

**Solution:** Extend `ScanContextParams` with taint/BP/ignored flags and optional path-filter fields. Single `build_run_config(cli, toml)` replaces two-phase construction.

**Impact:** Locality 8→9, Leverage 9→9.5. One place to read "what affects a scan."

- [x] Add `taint_*`, `bad_practices_*`, `show_ignored`, `bp_only` fields to `ScanContextParams`
- [x] Add `#[derive(Default)]` defaults for new fields
- [x] Move `scan_context_for_run()` post-hoc patches into `build_scan_context`
- [x] Evaluate folding `PathFilters` construction into params (or `RunConfig` wrapper) — `RunConfig` + `build_run_config()`
- [x] Update `app/run.rs` to use unified construction — remove local patches
- [x] Update `tests/engine_config_parsing.rs` if TOML fields change
- [x] Verify CLI + TOML merge behaviour unchanged

**Effort:** 3–4h.

### 2.2 Route All Discovery Through EntrySource

**Files:** `src/engine/walk/entry.rs`, `src/app/run.rs`, `src/engine/analyzer/scan.rs`

**Problem:** `collect_entries()` always calls `FilesystemWalker`, bypassing the `EntrySource` seam that `analyze_paths` respects. `run_prune_cache` uses the concrete path.

**Solution:** Thread optional `EntrySource` into `collect_entries` or route prune through `Analyzer` with injected source.

**Impact:** Seams 9→10. One discovery path for scan + prune + tests.

- [x] Add `collect_entries_with(source, ...)` seam alongside `collect_entries()` defaulting to `FilesystemWalker`
- [x] `run_prune_cache` uses `collect_entries()` → `FilesystemWalker` (prod default preserved)
- [x] Default to `FilesystemWalker` when no source injected (preserve prod behaviour)
- [x] Add tests for `collect_entries_with` + `FilesystemWalker` in `tests/engine_entry_source.rs`
- [x] Verify existing `tests/engine_entry_source.rs` still passes

**Effort:** 2–3h.

### 2.3 Close OutputReporter Bypass

**Files:** `src/app/run.rs`, `src/reporting/text/summary.rs`, `src/reporting/mod.rs`

**Problem:** `emit_output` bypasses `OutputReporter` when `no_terminal` is set, calling `write_no_terminal_summary` directly. Trait dispatch is not the sole output path.

**Solution:** Wrap summary-only output in a `TextReporter` variant or add `NoTerminalReporter` impl of `OutputReporter`.

**Impact:** Seams 9→9.5. All CLI output formats cross one seam.

- [x] Design minimal `OutputReporter` impl for no-terminal summary path (`NoTerminalReporter`)
- [x] Replace direct `write_no_terminal_summary` call in `emit_output`
- [x] Add trait-dispatch test for no-terminal variant in `tests/reporting_trait_dispatch.rs`
- [x] Verify terminal and no-terminal output unchanged

**Effort:** 1–2h.

---

## Phase 3: Test Surface Expansion (Worth Exploring)

### 3.1 Unit-Test Parallel Merge at Walk Seam

**Files:** `src/engine/walk/parallel.rs`, `tests/engine_parallel_merge.rs` (new)

**Problem:** `scan_entries_parallel`, preflight cache hits, and `merge_parallel_results` (~400 lines) have no direct unit tests — only observable via slow e2e scans.

**Solution:** New test file injecting `ListEntrySource` + pre-seeded `CacheStore::in_memory()`, assert `MergedScan` fields without Rayon/temp trees.

**Impact:** Testability 8→9. Interface is the test surface for merge logic.

- [x] Create `tests/engine_parallel_merge.rs`
- [x] Test cache-miss path: fresh entries produce expected `MergedScan` fields
- [x] Test cache-hit path: pre-seeded entries skip analysis, stats accumulate
- [x] Test error aggregation: mixed Ok/Err entries merge correctly
- [x] Use `ListEntrySource` + `CacheStore::in_memory()` — minimal temp dirs for fixture copy only
- [x] Verify tests run in &lt;100ms wall clock

**Effort:** 2–3h.

### 3.2 Exercise Global Timing Through with_timing()

**Files:** `src/engine/timing/collector.rs`, `tests/engine_observability_context.rs` (or new test)

**Problem:** `timing::with_timing()` exists (`#[cfg(test)]`) but has zero callers (`#[allow(dead_code)]`). Global timing merge after real `analyze_paths` is undertested.

**Solution:** Wrap a short `analyze_paths` call in `with_timing` with `collect_stats(true)`, assert non-empty `TimingSummary` phases.

**Impact:** Testability 8→8.5. Proves timing drain in `PipelineAccumulator::merge_chunk`.

- [x] Add unit tests in `src/engine/timing/tests.rs` calling `with_timing` (lib `#[cfg(test)]` only)
- [x] Assert `TimingSummary` has per-file and/or per-detector spans via `result.stats.timing`
- [x] Remove `#[allow(dead_code)]` from `with_timing`
- [x] Verify existing timing tests still pass

**Effort:** 1h.

### 3.3 Migrate Cache Integration Tests Off Disk I/O

**Files:** `tests/engine_cache_scan.rs`, `tests/engine_cache_invalidation.rs`, `tests/engine_cache_concurrent.rs`

**Problem:** Cache integration tests use `CacheStore::open*` + `unique_temp_root` despite `in_memory()` backend. Slow (~250ms), order-sensitive, harder to test edge cases.

**Solution:** Migrate tests that don't exercise filesystem-specific behaviour to `CacheStore::in_memory()`. Keep disk-backed tests for manifest/corruption/orphan paths.

**Impact:** Testability 8→9, Seams 9→9.5. Faster CI, concrete in-memory coverage.

- [x] Audit each test in `engine_cache_scan.rs` — classify disk-required vs logic-only
- [x] Migrate logic-only tests to `CacheStore::in_memory()` (`changing_source`, `deleting_file`, `oversized`)
- [x] Audit `engine_cache_invalidation.rs` — kept disk (multi-file project fixtures)
- [x] Audit `engine_cache_concurrent.rs` — kept disk (concurrent directory locking)
- [x] Keep disk-backed tests for: schema mismatch, corrupt manifest/entry, orphan cleanup, mtime drift
- [x] Added `CacheStore::in_memory_with_limits()` for size-limit tests

**Effort:** 2–3h.

---

## Phase 4: Leverage & Serialization (Worth Exploring)

### 4.1 Unified Rule-Metadata Codegen

**Files:** `build/gen_cwe.rs`, `build/gen_perf.rs`, `build/gen_bp.rs`

**Problem:** Three near-duplicate metadata generators differ mainly in id prefix and ref macro (~80 duplicated build lines).

**Solution:** Parameterize one `generate_rule_metadata(prefix, ref_macro, ids, rule_map)` function; three thin call sites.

**Impact:** Leverage 9→10. Metadata shape defined once.

- [x] Extract shared `generate_go_rule_metadata_code` in `build/gen_metadata.rs`
- [x] Refactor `gen_cwe.rs` to call shared generator
- [x] Refactor `gen_perf.rs` to call shared generator
- [x] Refactor `gen_bp.rs` to call shared generator (`generate_go_bp_metadata_code` in `gen_metadata.rs`)
- [x] Verify generated registries byte-identical (or diff only whitespace)
- [x] Verify all detector integration tests pass

**Effort:** 2–3h.

### 4.2 Centralize Finding Serialization

**Files:** `src/rules/finding_wire.rs`, `src/reporting/json/types.rs`, `src/export/finding_block.rs`, `src/reporting/text/render.rs`

**Problem:** `Finding` has 3 wire shapes — core struct, `FindingWire` (full field mirror + `From`), `FindingJson`. Adding a finding field touches 4–6 files. SARIF tag logic partially re-implements category prefix checks.

**Solution:** Shared `FindingView` or derive JSON wire from `Finding` + thin format adapters.

**Impact:** Locality 8→9. Finding-field touch count drops from 4–6 to 2–3.

- [x] Map all finding field consumers (JSON, SARIF, text, export)
- [x] Design shared view type or derive-based wire layer — `FindingView<'a>` in `src/rules/finding_view.rs`
- [x] Migrate `FindingWire` to use shared view — `from_finding()` centralizes owned mapping; cache path unchanged
- [x] Migrate `FindingJson` to use shared view
- [x] Migrate `finding_block.rs` and `text/render.rs` field enumeration
- [x] Fix SARIF tag logic to use `category_for_rule_id` consistently (`sarif_tags_for_finding`)
- [x] Verify reporting snapshot tests pass

**Effort:** 4–6h. Larger change — do after Phase 1–3.

### 4.3 Deepen App Run Orchestration

**Files:** `src/app/run.rs` (~501 lines)

**Problem:** `run_scan` wires config, cache, baseline, export, diagnostics, and exit codes with no abstraction. Deletion would scatter orchestration. Not testable through library interface.

**Solution:** `ScanRun::execute(cli) -> ScanOutcome` hiding post-scan baseline/export/diagnostics.

**Impact:** Depth 8→9, Testability 8→9. Behaviour behind small interface.

- [x] Define `ScanRun` struct holding CLI-derived config
- [x] Extract `execute()` method orchestrating config → scan → output → exit
- [x] Move baseline filter/store logic behind `ScanRun` (via `execute()` orchestration)
- [x] Move export/diagnostics wiring behind `ScanRun`
- [x] Slim `run_scan()` to delegate to `ScanRun::execute`
- [x] Add unit test for `ScanRun` with mocked/in-memory dependencies (`scan_run_builds_via_run_config`)
- [x] Verify subprocess baseline tests still pass

**Effort:** 4–6h. **Speculative** — defer until CLI surface stabilizes.

---

## Phase 5: Embedder Seams & Deferred Polish (Speculative)

### 5.1 Expose Registry / CacheBackend Injection

**Files:** `src/engine/analyzer/builder.rs`, `src/engine/cache/store_open.rs`, `src/engine/registry.rs`

**Problem:** `AnalyzerBuilder::build` hardcodes `Registry::default()`. `Registry::from_plugins` is `pub(crate)`. Custom plugins and third backends require crate edits.

**Solution:** `AnalyzerBuilder::registry(...)`, `CacheStore::with_backend(...)`.

**Impact:** Seams 9→10 for external embedders. Unlocks remote cache / custom language without forking.

- [x] Add `AnalyzerBuilder::registry(Registry)` method
- [x] Make `Registry::from_plugins` public (or provide `Registry::with_plugins`)
- [x] Add `CacheStore::with_backend(Box<dyn CacheBackend>)` constructor
- [x] Document embedder API in crate docs — public `CacheBackend`, `InMemoryBackend`, `Registry::with_plugins`
- [x] Add example test constructing custom in-memory backend (`tests/engine_embedder_seams.rs`)

**Effort:** 2–3h. **Defer until embedder demand is real.**

### 5.2 Cache Session Handle

**Files:** `src/engine/cache/mod.rs`, `src/engine/analyzer/scan.rs`, `src/app/cache.rs`

**Problem:** Integrators see full `CacheStore` CRUD/eviction API (`open_with_*`, `lookup`, `put`, `prune`, `invalidate_*`, `flush`, `manifest`). Wide interface for what scans actually need.

**Solution:** `CacheSession` created per scan, exposing only `as_mut()` to engine; prune/rebuild stay in app helpers.

**Impact:** Depth 8→9. Interface shrinks for scan callers.

- [x] Define `CacheSession` wrapper with minimal surface (`src/engine/cache/session.rs`)
- [x] Route `analyze_paths` through session handle
- [x] Keep full `CacheStore` for app-level prune/rebuild
- [x] Verify no behavioural change (`tests/engine_cache_session.rs`)

**Effort:** 3–4h. **Defer** — wide surface is tolerable today.

### 5.3 Plugin Registration Inventory

**Files:** `src/lang/mod.rs`, `src/lang/go/detectors/mod.rs`

**Problem:** `enabled_plugins()` and `detectors::all()` use manual `#[cfg(feature)]` + `vec!` per language/detector. Scales linearly with feature count.

**Solution:** `inventory` crate or `linkme` slice of `fn() -> Box<dyn LanguagePlugin>`.

**Impact:** Leverage 9→9.5. **Low payoff until language count &gt;3** (today: 2).

- [x] Evaluate `inventory` vs `linkme` for auto-registration — chose `inventory` (linker-section, no proc-macro)
- [x] Prototype with Go + Python plugins (`src/lang/*/register.rs`)
- [x] Assess compile-time vs binary-size tradeoffs — acceptable; feature-gated `inventory::submit!`
- [x] `tests/lang_plugin_inventory.rs` verifies registrar collection

**Effort:** 4–5h. **YAGNI today.**

### 5.4 Orphaned CWE Domain Files

**Files:** `src/lang/go/detectors/cwe/domains/`

**Problem:** Cosmetic structural inconsistency in domain module layout. No functional impact.

**Solution:** Audit and consolidate orphaned re-exports / empty domain stubs.

- [x] Inventory domain `mod.rs` re-export lists vs actual modules
- [x] Remove or merge orphaned files — audit found no orphans; all `.rs` files declared in parent `mod.rs`
- [x] Verify detector registry unchanged

**Effort:** 1–2h. **Low priority.**

### 5.5 Large Detector File Splits

**Files:** `src/lang/go/detectors/cwe/`, `src/lang/go/detectors/perf/`

**Problem:** Individual detector and taint files are large. Tracing one rule spans `taint/rules/`, `graph_query/`, `facts/`, `model.rs`.

**Solution:** **Defer — YAGNI.** Domain complexity is expected; split pattern not yet proven across all domains.

- [x] Document split criteria (file &gt;500 lines AND multiple independent concepts) in `perf/domains/mod.rs`
- [x] Applied split: `stdlib_optimization/` → `handler_limits.rs` + `io_and_runtime.rs`

**Effort:** 2h.

---

## Module Graph Summary

| Candidate | Depth | Seams | Locality | Testability | Leverage | Effort | Phase |
|-----------|-------|-------|----------|-------------|----------|--------|-------|
| 1.1 Collapse ScanOutcome | — | — | +1 | — | — | 2–3h | 1 |
| 1.2 ScanStats::merge final | — | — | +0.5 | — | — | 1h | 1 |
| 2.1 Unify config construction | — | — | +1 | — | +0.5 | 3–4h | 2 |
| 2.2 EntrySource everywhere | — | +1 | — | +0.5 | — | 2–3h | 2 |
| 2.3 Close OutputReporter bypass | — | +0.5 | — | — | — | 1–2h | 2 |
| 3.1 Parallel merge unit tests | — | — | — | +1 | — | 2–3h | 3 |
| 3.2 Exercise with_timing() | — | — | — | +0.5 | — | 1h | 3 |
| 3.3 Migrate cache integration tests | — | +0.5 | — | +1 | — | 2–3h | 3 |
| 4.1 Unified metadata codegen | — | — | — | — | +1 | 2–3h | 4 |
| 4.2 Centralize finding serialization | — | — | +1 | — | — | 4–6h | 4 |
| 4.3 ScanRun orchestration | +1 | — | — | +1 | — | 4–6h | 4 |
| 5.1 Registry/backend injection | — | +1 | — | — | — | 2–3h | 5 |
| 5.2 Cache session handle | +1 | — | — | — | — | 3–4h | 5 |

### Recommended Order

1. **Phase 1** (3–4h) — mechanical pipeline locality, zero behavioural risk
2. **Phase 2.1 + 2.2** (5–7h) — config + discovery seam closure
3. **Phase 3.1 + 3.2** (3–4h) — test the shapes locked by Phase 1
4. **Phase 2.3 + 3.3** (3–5h) — remaining seam closure + faster CI
5. **Phase 4.1** (2–3h) — build-script leverage when touching build anyway
6. **Phase 4.2–4.3, Phase 5** — defer until friction is felt in practice

---

## Change Impact Reference (Current Baseline)

| Change type | Files touched | Notes |
|-------------|---------------|-------|
| Add pipeline counter (in `ScanStats`) | 4–5 | `stats/scan.rs`, `scan_entry.rs`, `parallel.rs`, `analyzer/scan.rs`, optional `diagnostics/` |
| Add pipeline counter (new top-level field) | 4 | `scan_entry.rs`, `parallel.rs`, `result.rs`, `analyzer/scan.rs` — drops to 2 after 1.1 |
| Add `ScanContext` CLI option | 3–4 | `core/scan/context.rs`, `scan_context.rs`, `app/run.rs`, tests |
| Add `codehound.toml` option | 5–7 | `types.rs`, `discover.rs`, `scan_context.rs`, `cli/args.rs`, `app/run.rs`, tests |
| Add `Finding` field | 4–6 | `finding.rs`, `finding_wire.rs`, `json/types.rs`, + text/export/SARIF — drops to 2–3 after 4.2 |

---

## Completed Prior Work (Context Only)

The following were completed in `plan-improvements-06072026.md` and verified present in current code:

- [x] Pipeline named structs (`ScanEntryResult`, `MergedScan`, `PipelineAccumulator`)
- [x] `ScanContextParams` + `Default`
- [x] `CacheBackend` trait (`DiskBackend` + `InMemoryBackend`)
- [x] Global timing collector
- [x] `TreeSitterLang` + `tree_sitter_lang!` macro
- [x] `OutputReporter` trait + polymorphic tests
- [x] `EntrySource` trait (`FilesystemWalker` + `ListEntrySource`)
- [x] `PipelineAccumulator` unit tests (6 tests)
- [x] Dead code cleanup (`AnalysisResultBuilder`, `capture_reporter_output`)
- [x] `ListEntrySource` exported + `tests/engine_entry_source.rs`
- [x] `CacheError::Corrupt` variant

---

## Post-Implementation Re-Rating (2026-07-06)

Five subagents re-scanned live Rust code after all plan items landed.

| Dimension | Before | After | Δ |
|-----------|--------|-------|---|
| Depth | 8/10 | **8.4/10** | +0.4 |
| Seams | 9/10 | **8.9/10** | −0.1 |
| Locality | 8/10 | **7.8/10** | −0.1 |
| Testability | 8/10 | **8.3/10** | +0.3 |
| Leverage | 9/10 | **9.0/10** | 0 |

**Overall: 8.4 → 8.5/10** (~317 tests passing)

### After push-to-10 follow-up

| Dimension | Post-plan | After follow-up |
|-----------|-----------|-----------------|
| Depth | 8.4 | 8.4 |
| Seams | 8.9 | **9.0** |
| Locality | 7.8 | **9.0** |
| Testability | 8.3 | **8.5** |
| Leverage | 9.0 | 9.0 |

**Overall: ~8.8/10**

### Push-to-10 follow-up (2026-07-06, second pass)

- [x] Migrate SARIF (`log.rs`) and text summary to `FindingView`
- [x] `sarif_tags_for_finding` delegates to `FindingView::sarif_tags()`
- [x] `FindingWire::from_finding` reads scalars through `FindingView`
- [x] Analyzer always holds `Box<dyn EntrySource>` (default `FilesystemWalker`)
- [x] `run_prune_cache` uses `collect_entries_with(&FilesystemWalker, ...)`
- [x] `append_file_contribution` deduplicates parallel merge arms
- [x] Extended `CacheSession` integration test (put/invalidate)

Remaining friction toward 10: per-rule `detect_*` + TOML registry rows stay manual (~150 domain files); `FindingWire` still owns a parallel struct for cache serde; detector auto-registration not implemented.

## HTML Report Reference

- Pre-plan scan: `/tmp/architecture-review-20260706-185502.html`
- Post-implementation: `/tmp/architecture-review-20260706-195342.html`