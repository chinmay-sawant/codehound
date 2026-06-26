# Phase 1 — Engine / AST / Core / CWE

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** Not started. All sections are planning only — no source files have been moved yet.
> **Estimated effort:** 1-1.5 weeks. ~80 new files. Touches the most cross-referenced area of the codebase; do last within Phase 1.

---

## Overview

Split every oversized file under `src/engine/`, `src/ast/`, `src/core/`,
`src/cwe/`, `src/lang/go/detectors/cwe/taint/`, and
`src/lang/go/detectors/cwe/facts.rs` into focused sub-modules. Public
API is preserved through `pub use` re-exports at every new `mod.rs`.

**Scope:** `src/engine/`, `src/ast/`, `src/core/`, `src/cwe/`,
`src/lang/go/detectors/cwe/taint/`, `src/lang/go/detectors/cwe/facts.rs`.

**Files covered:** 22 (12 require splitting, 10 are unchanged or optional).
**New files:** ~80.

---

## Executive Summary

- **Problem:** Engine files dominate the largest-file list (`walk.rs` 27.9 KB, `cache.rs` 24.7 KB, `dependencies.rs` 21.0 KB, `config.rs` 9.2 KB). The taint subsystem and `cwe/facts.rs` are the most cross-referenced.
- **Approach:** Convert each `.rs` file into a folder of focused sub-modules. Every new `mod.rs` is private; public surface is re-exported with `pub use`. Leave the `pub mod sinks;` exception in `engine/mod.rs` intact.
- **Success criteria:** All 22 files in scope are either split or confirmed under 3 000 chars. Public symbols remain reachable at the same path. `cargo build --features go && cargo test --lib --features go` is green after every batch.
- **Trade-offs:** `cache/store.rs` may need a further split (~13 000 chars after first split). `engine/walk/parallel.rs` will be ~7 500 chars. Both are in the 4 000–6 000 exception band.
- **Open questions:** Should `src/ast/function.rs` be split? (Recommendation: leave as-is, 3 366 chars is borderline.)

---

## Module-pattern reference (apply to every section below)

| Pattern | Where | Implication |
|---|---|---|
| `mod foo;` + `pub use foo::{…};` in parent `mod.rs` | `engine/mod.rs`, `ast/mod.rs`, `core/mod.rs`, `cwe/mod.rs`, `taint/mod.rs` | After a split, the same `mod foo;` line still resolves to either a file or a folder. Add the new `pub use` in the new `foo/mod.rs`. |
| `pub mod foo;` | only `engine/sinks;` (deliberate exception) and `cwe::common` | The new sub-modules stay private; `pub use` in the new `mod.rs` re-exports the public surface. |
| `include!(concat!(env!("OUT_DIR"), "/foo.rs"))` | `src/cwe/catalog.rs`, `src/lang/go/detectors/cwe/metadata.rs`, etc. | The file containing the `include!` is load-bearing. Splits must keep the `include!` directive in the file that owns the corresponding `pub(super) const` items. |

For consistency with the rest of the codebase, every new sub-module
declared by a `mod.rs` is **private**; the public surface is re-exported
with `pub use`.

---

## Phase 1.1: `src/engine/walk.rs` → `src/engine/walk/`

**Current size:** 27 909 chars / 786 lines.
**Top-level items:** `ScanEntry`, `collect_entries`, `RootPathMatcher`, `build_globset`, `scan_entry`, `attach_function_context`, `analyze_parsed_unit`, `analyze_parsed_unit_with_context`, `ScanOutcome`, `scan_entries_parallel`, `filter_cached_findings`, `mtime_of`, `bytecount_lines`, `panic_message`, `scratch_contains`.
**External re-exports in `engine/mod.rs`:** `analyze_parsed_unit`, `analyze_parsed_unit_with_context`, `collect_entries`, `scratch_contains`.
**External users:** `src/app.rs:12`, `benches/scan_throughput.rs:8`, `benches/incremental_scan.rs:23`, and many detector files via `crate::engine::scratch_contains`.

### Proposed file tree

- [ ] Create `src/engine/walk/mod.rs` with `mod` declarations + `pub use {collect_entries, scratch_contains, analyze_parsed_unit, analyze_parsed_unit_with_context};` (~200 chars)
- [ ] Create `src/engine/walk/entry.rs` with `pub struct ScanEntry` + `pub fn collect_entries` + `struct RootPathMatcher` + `fn build_globset` (~4 500 chars)
- [ ] Create `src/engine/walk/parallel.rs` with `pub enum ScanOutcome` + `pub fn scan_entries_parallel` + `fn filter_cached_findings` + `fn mtime_of` + `fn bytecount_lines` + `fn panic_message` (~7 500 chars)
- [ ] Create `src/engine/walk/scan_entry.rs` with `pub fn scan_entry` + `fn attach_function_context` (~6 500 chars)
- [ ] Create `src/engine/walk/analyze.rs` with `pub fn analyze_parsed_unit` + `pub fn analyze_parsed_unit_with_context` (~2 000 chars)
- [ ] Create `src/engine/walk/scratch.rs` with `pub fn scratch_contains` + its `thread_local!` buffer (~1 200 chars)
- [ ] Delete `src/engine/walk.rs`
- [ ] In `engine/mod.rs`, replace existing `mod walk; pub use walk::{…};` with `mod walk;` (the new `walk/mod.rs` re-exports the public surface)

### Compatibility notes

- [ ] `scan_entry`, `scan_entries_parallel`, `ScanEntry`, `ScanOutcome` are not currently re-exported at the engine level. They become `pub(crate)` (or stay reachable at `crate::engine::walk::…`).
- [ ] No test or bench edits required.

---

## Phase 1.2: `src/engine/cache.rs` → `src/engine/cache/`

**Current size:** 24 711 chars / 698 lines.
**Top-level items:** `CACHE_VERSION`, `DEFAULT_CACHE_DIR`, `CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`, `CacheLookup`, `CacheError`, `MANIFEST_NAME`, `METADATA_NAME`, `FILES_SUBDIR`, `pub struct CacheStore` + 18 methods + `Drop`, `content_hash`, `cache_key_for_path`, `hex_lower`, `mtime_of_file`, `write_atomic`, `iso8601_now`, `iso8601_utc_now`, `iso8601_from_mtime`, `iso8601_from_secs`, `unix_epoch_to_ymdhms`, `#[cfg(test)] mod tests`.

### Proposed file tree

- [ ] Create `src/engine/cache/mod.rs` with `mod` declarations + `pub use` re-exports for every currently-public item (~700 chars)
- [ ] Create `src/engine/cache/types.rs` with `CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`, `CacheLookup`, `CacheError`, constants (~2 800 chars)
- [ ] Create `src/engine/cache/hash.rs` with `content_hash`, `cache_key_for_path`, `hex_lower`, `iso8601_now` + private ISO-8601 helpers (~2 200 chars)
- [ ] Create `src/engine/cache/io.rs` with `mtime_of_file`, `write_atomic` (~1 100 chars)
- [ ] Create `src/engine/cache/store.rs` with `pub struct CacheStore` + 18 methods + `Drop` (~13 000 chars)
- [ ] Create `src/engine/cache/tests.rs` with `#[cfg(test)] mod tests` (3 tests) (~1 200 chars)
- [ ] Delete `src/engine/cache.rs`
- [ ] In `engine/mod.rs`, replace `mod cache; pub use cache::{…};` with `mod cache;`. The new `cache/mod.rs` re-exports the entire public surface.

### Optional further split of `store.rs` if ~13 000 chars is too large

- [ ] `cache/store_open.rs` (constructor, accessors, manifest)
- [ ] `cache/store_lifecycle.rs` (`put`, `remove`, `prune`, `clean_orphans`, `invalidate_*`)
- [ ] `cache/store_flush.rs` (`flush` + `evict_to_size`)

### Compatibility notes

- [ ] Internal users `walk.rs` and `analyzer.rs` continue to write `crate::engine::cache::…` (path unchanged).
- [ ] `Drop for CacheStore` stays in `store.rs`.
- [ ] `evict_to_size` calls `self.read_entry` (private). Keep it in `store.rs` to avoid making the helper `pub(crate)`.

---

## Phase 1.3: `src/engine/dependencies.rs` → `src/engine/dependencies/`

**Current size:** 21 005 chars / 609 lines.
**Top-level items:** `extensions_for`, `extract_dependencies`, `go_module_prefix`, `discover_project_root`, inner `mod go {…}` and `mod python {…}`, shared `resolve_local_path` / `visit_dir`, `#[cfg(test)] mod tests`.

### Proposed file tree

- [ ] Create `src/engine/dependencies/mod.rs` with `mod` decls + `pub use {discover_project_root, extract_dependencies, go_module_prefix};` (~250 chars)
- [ ] Create `src/engine/dependencies/entry.rs` with `pub fn extract_dependencies` + `fn extensions_for` (language-dispatch) (~3 500 chars)
- [ ] Create `src/engine/dependencies/go_module.rs` with `pub fn go_module_prefix` (~700 chars)
- [ ] Create `src/engine/dependencies/project_root.rs` with `pub fn discover_project_root` (~1 200 chars)
- [ ] Create `src/engine/dependencies/go_imports.rs` with the entire `mod go {…}` block (~5 800 chars)
- [ ] Create `src/engine/dependencies/python_imports.rs` with the entire `mod python {…}` block (~6 800 chars)
- [ ] Create `src/engine/dependencies/resolve.rs` with shared `resolve_local_path` + `visit_dir` (now `pub(super) fn`) (~1 800 chars)
- [ ] Create `src/engine/dependencies/tests.rs` with `#[cfg(test)] mod tests` + `tempfile_root` helper (~1 100 chars)
- [ ] Delete `src/engine/dependencies.rs`
- [ ] In `engine/mod.rs`, replace `mod dependencies; pub use dependencies::{…};` with `mod dependencies;` (re-exports move into new `dependencies/mod.rs`)

### Compatibility notes

- [ ] `extensions_for` moves into `resolve.rs` as `pub(super) fn`; the internal Go and Python modules adjust to `use super::super::resolve::extensions_for;`.

---

## Phase 1.4: `src/engine/config.rs` → `src/engine/config/`

**Current size:** 9 209 chars / 326 lines.
**Top-level items:** `SlopguardConfig`, `SlopguardSection`, `BaselineConfig`, `CacheConfig`, `TaintConfig`, `BadPracticesConfig`, `PathFilters`, the ~17-method `impl SlopguardConfig`, `discover_cache_dir`, `fail_on_to_policy`, `discover_config`, `load_discovered_config`, `build_scan_context`.

### Proposed file tree

- [ ] Create `src/engine/config/mod.rs` with `mod` decls + `pub use` for all 10 currently re-exported items (~500 chars)
- [ ] Create `src/engine/config/types.rs` with all `#[derive(Deserialize)]` structs + their `Default` impls (~3 500 chars)
- [ ] Create `src/engine/config/section.rs` with `impl SlopguardConfig` (the ~17 accessors + `load` + `discover` + `merge_into`) (~4 200 chars)
- [ ] Create `src/engine/config/discover.rs` with `discover_cache_dir`, `discover_config`, `load_discovered_config`, `fail_on_to_policy` (~1 600 chars)
- [ ] Create `src/engine/config/scan_context.rs` with `build_scan_context` (~1 300 chars)
- [ ] Delete `src/engine/config.rs`

---

## Phase 1.5: `src/engine/analyzer.rs` → `src/engine/analyzer/`

**Current size:** 8 773 chars / 264 lines.
**Top-level items:** `AnalyzerBuilder`, `Analyzer`, `sort_findings`.

### Proposed file tree

- [ ] Create `src/engine/analyzer/mod.rs` with `mod` decls + `pub use {Analyzer, AnalyzerBuilder};` (~150 chars)
- [ ] Create `src/engine/analyzer/types.rs` with struct definitions + builder accessors (~3 000 chars)
- [ ] Create `src/engine/analyzer/scan.rs` with `Analyzer::analyze_paths` + cascade-invalidation / pruning (~4 800 chars)
- [ ] Create `src/engine/analyzer/units.rs` with `Analyzer::analyze_units` + `sort_findings` (~1 500 chars)
- [ ] Delete `src/engine/analyzer.rs`

---

## Phase 1.6: `src/engine/timing.rs` → `src/engine/timing/`

**Current size:** 6 870 chars / 227 lines.

### Proposed file tree

- [ ] Create `src/engine/timing/mod.rs` with `mod` decls + `pub use {PhaseTiming, TimingCollector, TimingSpan, TimingSummary};` (~250 chars)
- [ ] Create `src/engine/timing/collector.rs` with `TimingSpan`, `TimingCollector` + impl (~3 500 chars)
- [ ] Create `src/engine/timing/summary.rs` with `TimingSummary` + impl + `PhaseTiming` (~3 000 chars)
- [ ] Create `src/engine/timing/serde.rs` with `mod duration_millis` helper (~700 chars)
- [ ] Create `src/engine/timing/tests.rs` with `#[cfg(test)] mod tests` (3 tests) (~1 100 chars)
- [ ] Delete `src/engine/timing.rs`

---

## Phase 1.7: `src/engine/baseline.rs` → `src/engine/baseline/`

**Current size:** 6 463 chars / 201 lines.

### Proposed file tree

- [ ] Create `src/engine/baseline/mod.rs` with `mod` decls + `pub use {BASELINE_FILE_NAME, BASELINE_VERSION, Baseline, BaselineEntry, discover_baseline};` (~250 chars)
- [ ] Create `src/engine/baseline/entry.rs` with `BaselineEntry` + private `BaselineLocationKey` (~700 chars)
- [ ] Create `src/engine/baseline/store.rs` with `Baseline` + its 7-method impl (~3 500 chars)
- [ ] Create `src/engine/baseline/io.rs` with `discover_baseline` + duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms` (~1 800 chars)
- [ ] Delete `src/engine/baseline.rs`

---

## Phase 1.8: `src/engine/diagnostics.rs` → `src/engine/diagnostics/`

**Current size:** 5 469 chars / 172 lines.

### Proposed file tree

- [ ] Create `src/engine/diagnostics/mod.rs` with `mod` decls + `pub use {Diagnostics, ScanDiagnostics, FindingsDiagnostics, TimingDiagnostics, DetectorsDiagnostics, RuleTiming};` (~250 chars)
- [ ] Create `src/engine/diagnostics/types.rs` with the five `#[derive(Serialize)]` sub-structs (~1 800 chars)
- [ ] Create `src/engine/diagnostics/build.rs` with `pub struct Diagnostics` + `impl Diagnostics::from_stats` (~2 800 chars)
- [ ] Create `src/engine/diagnostics/clock.rs` with the duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms` (~1 100 chars)
- [ ] Delete `src/engine/diagnostics.rs`

---

## Phase 1.9: `src/engine/stats.rs` → `src/engine/stats/`

**Current size:** 4 745 chars / 146 lines.

### Proposed file tree

- [ ] Create `src/engine/stats/mod.rs` with `mod` decls + `pub use {FileStats, ScanStats};` (~150 chars)
- [ ] Create `src/engine/stats/scan.rs` with `ScanStats` + `impl` (~3 200 chars)
- [ ] Create `src/engine/stats/file.rs` with `FileStats` + `impl` (~1 000 chars)
- [ ] Delete `src/engine/stats.rs`

---

## Phase 1.10: `src/engine/ignore.rs` → `src/engine/ignore/`

**Current size:** 4 579 chars / 183 lines.

### Proposed file tree

- [ ] Create `src/engine/ignore/mod.rs` with `mod` decls + `pub use {IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore, parse_inline_ignores};` (~250 chars)
- [ ] Create `src/engine/ignore/directive.rs` with `IgnoreDirective` + its impl (~900 chars)
- [ ] Create `src/engine/ignore/parse.rs` with `parse_inline_ignores`, `parse_file_ignore`, private helpers (~2 000 chars)
- [ ] Create `src/engine/ignore/apply.rs` with `apply_inline_ignores`, `apply_file_ignore`, `apply_directive` (~1 700 chars)
- [ ] Delete `src/engine/ignore.rs`

---

## Phase 1.11: `src/engine/registry.rs` — **no split**

**Current size:** 2 885 chars / 95 lines.
- [ ] Confirm under 3 000-char ceiling — single `impl Registry` block. **No work.**

## Phase 1.12: `src/engine/result.rs` — **no split**

**Current size:** 2 774 chars / 87 lines.
- [ ] Confirm under 3 000-char ceiling. **No work.**

## Phase 1.13: `src/engine/language_filter.rs` — **no split**

**Current size:** 2 302 chars / 75 lines.
- [ ] Confirm under 3 000-char ceiling. **No work.**

---

## Phase 1.14: `src/ast/function.rs` — **optional split**

**Current size:** 3 366 chars / 102 lines.

- [ ] **Recommendation: leave as-is.** Slightly over the 3 000 ceiling but tight.
- [ ] If a split is required: `ast/function/span.rs` (~1 500) + `ast/function/collect.rs` (~1 700)

---

## Phase 1.15: `src/core/scan.rs` → `src/core/scan/`

**Current size:** 3 523 chars / 117 lines.

### Proposed file tree

- [ ] Create `src/core/scan/mod.rs` with `mod` decls + `pub use {FailPolicy, ScanContext};` (~150 chars)
- [ ] Create `src/core/scan/policy.rs` with `pub enum FailPolicy` + impl (~700 chars)
- [ ] Create `src/core/scan/context.rs` with `pub struct ScanContext` + `Default` + impl (~2 500 chars)
- [ ] Create `src/core/scan/filter.rs` with private `fn rule_matches` (~400 chars)
- [ ] Delete `src/core/scan.rs`

---

## Phase 1.16: `src/core/language.rs` → `src/core/language/`

**Current size:** 3 255 chars / 99 lines.

### Proposed file tree

- [ ] Create `src/core/language/mod.rs` with `mod` decls + `pub use {LanguageId, LanguagePlugin};` (~150 chars)
- [ ] Create `src/core/language/id.rs` with `LanguageId` + impl (~1 800 chars)
- [ ] Create `src/core/language/plugin.rs` with `trait LanguagePlugin` (~1 600 chars)
- [ ] Delete `src/core/language.rs`

---

## Phase 1.17: `src/cwe/catalog.rs` → `src/cwe/catalog/`

**Current size:** 3 899 chars / 112 lines.

### Proposed file tree

- [ ] Create `src/cwe/catalog/mod.rs` with `mod` decls + `pub use` of all 8 currently re-exported items (~500 chars)
- [ ] Create `src/cwe/catalog/consts.rs` with the 6 hand-written `CWE_*` consts + `CWE_CATALOG` + `CWE_REFS_*` slices + `include!(.../cwe_catalog_generated.rs)` (~1 700 chars)
- [ ] Create `src/cwe/catalog/description.rs` with `RuleDescription` + `load_rule_descriptions` + `default_ruleset_path` + `include!(.../rule_catalogue.rs)` + the `deserialize_id` helper (~1 900 chars)
- [ ] Delete `src/cwe/catalog.rs`

### Caveat

- [ ] Both `include!` directives are textual inclusions of build-script output. Both must stay in the same file that owns the corresponding generated `pub static` / `pub fn` items.

---

## Phase 1.18: `src/lang/go/detectors/cwe/taint/mod.rs` → `taint/`

**Current size:** 7 720 chars / 245 lines.
**Special:** This file is the public entry of the taint subsystem. The existing children (`extract.rs`, `graph.rs`, `rules.rs`) are large and also need splitting (see §1.19–1.21). After the children are split, this `mod.rs` becomes a thin re-exporter.

### Proposed new `taint/mod.rs`

- [ ] Replace the existing `taint/mod.rs` with the new layout:
  ```rust
  mod graph;            // data model (SourceKind, SinkKind, etc.) — new
  mod graph_query;      // was: graph
  mod kinds;            // new
  mod model;            // new (holds the structs/enums currently in mod.rs)
  pub mod extract;
  pub mod graph_query;  // re-exported as before
  pub mod rules;

  pub use extract::extract_taint_facts;
  pub use graph_query::{TaintPath, build_taint_graph, find_taint_paths};
  pub use rules::{detect_cwe_22_taint, detect_cwe_78_taint,
                  detect_cwe_79_taint, detect_cwe_89_taint};
  ```

### Rename: `taint/graph.rs` → `taint/graph_query.rs`

- [ ] Rename `taint/graph.rs` → `taint/graph_query.rs` to free the name `graph` for the new data-model file.
- [ ] Update `taint/mod.rs` to `pub mod graph_query;` and re-export from there.

---

## Phase 1.19: `src/lang/go/detectors/cwe/taint/extract.rs` → `extract/`

**Current size:** 16 609 chars / 549 lines.

### Proposed file tree

- [ ] Create `src/lang/go/detectors/cwe/taint/extract/mod.rs` with `mod` decls + `pub use {extract_taint_facts};` (~300 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/extract/walker_core.rs` with `extract_taint_facts` + `ExtractionState` + `walk_node` + `is_chained_call` (~3 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/extract/walker_records.rs` with `record_call` + `record_assignment` + `result_variable_of_call` + `argument_texts` (~3 200 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/extract/classify.rs` with `classify_source` + `classify_sink` + `classify_sanitizer` + `receiver_of_method_call` + `is_template_html_call` + `is_source_or_sanitizer_call` (~3 700 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/extract/assignments.rs` with `split_assignment` + `extract_identifiers` (~700 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/extract/tests.rs` with `#[cfg(test)] mod tests` (4 tests) (~2 500 chars)
- [ ] Delete `src/lang/go/detectors/cwe/taint/extract.rs`

---

## Phase 1.20: `src/lang/go/detectors/cwe/taint/graph.rs` → `graph_query/`

**Current size:** 13 275 chars / 418 lines.

### Proposed file tree (after rename to `graph_query.rs` per §1.18)

- [ ] Create `src/lang/go/detectors/cwe/taint/graph_query/mod.rs` with `mod` decls + `pub use {TaintPath, build_taint_graph, find_taint_paths};` (~250 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/graph_query/build.rs` with `build_taint_graph` + `wire_arguments` + `resolve_variable` + `referenced_identifiers` + `is_go_keyword` + `as_simple_identifier` (~4 800 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/graph_query/query.rs` with `TaintPath` + `find_taint_paths` + `bfs_path` + `is_sanitizer` (~4 000 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/graph_query/tests.rs` with `#[cfg(test)] mod tests` (4 tests) (~3 000 chars)
- [ ] Delete `src/lang/go/detectors/cwe/taint/graph.rs`

---

## Phase 1.21: `src/lang/go/detectors/cwe/taint/rules.rs` → `rules/`

**Current size:** 7 231 chars / 237 lines.

### Proposed file tree

- [ ] Create `src/lang/go/detectors/cwe/taint/rules/mod.rs` with `mod` decls + `pub use {detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint};` (~300 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/rules/cwe_22.rs` with `detect_cwe_22_taint` (~2 000 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/rules/cwe_78.rs` with `detect_cwe_78_taint` (~1 900 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/rules/cwe_79.rs` with `detect_cwe_79_taint` (~1 900 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/rules/cwe_89.rs` with `detect_cwe_89_taint` (~1 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/taint/rules/evidence.rs` with `variable_name_at` + `source_info` (~700 chars)
- [ ] Delete `src/lang/go/detectors/cwe/taint/rules.rs`

---

## Phase 1.22: `src/lang/go/detectors/cwe/facts.rs` → `facts/`

**Current size:** 6 093 chars / 215 lines.

### Proposed file tree

- [ ] Create `src/lang/go/detectors/cwe/facts/mod.rs` with `mod` decls + `pub use` of public types + public helpers (~500 chars)
- [ ] Create `src/lang/go/detectors/cwe/facts/types.rs` with `InputKind`, `InputBinding`, `CallFact`, `AssignmentFact`, `GoUnitFacts` (~1 700 chars)
- [ ] Create `src/lang/go/detectors/cwe/facts/build.rs` with `build_go_unit_facts` + `build_taint_graph_for_facts` (~1 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/facts/interner.rs` with `SharedTextInterner` + impl + `extract_argument_texts` + `record_call_fact` + `record_assignment_fact` (all `pub(crate)`) (~2 000 chars)
- [ ] Create `src/lang/go/detectors/cwe/facts/expr_patterns.rs` with `split_assignment` + `extract_identifiers` + `is_user_input_expr` + `is_trusted_config_expr` (~1 200 chars)
- [ ] Delete `src/lang/go/detectors/cwe/facts.rs`

### Caveat

- [ ] `lang/go/detectors/facts.rs:2-7` aliases `SharedTextInterner as CweInterner`, `record_call_fact as record_cwe_call`, `record_assignment_fact as record_cwe_assign`. After the split, those become `crate::lang::go::detectors::cwe::facts::interner::{…}` but must remain `pub(crate) use` re-exported from `facts/mod.rs`.

---

## Phase 1.23: Duplicates flagged for de-duplication

These are not in the strict scope of the split but are removed as a side-effect:

- [ ] **`iso8601_utc_now` + `unix_epoch_to_ymdhms`** — duplicated across `cache.rs`, `baseline.rs`, `diagnostics.rs`, `reporting/sarif.rs`. The split moves each copy to its per-file `clock.rs` (or `time.rs`). A future cleanup would extract them into a single `engine/time.rs` (~120 lines saved).
- [ ] **`split_assignment` + `extract_identifiers`** — duplicated across `cwe/facts.rs`, `cwe/taint/extract.rs`, `perf/facts.rs`. A future cleanup would move them to a single `lang/go/detectors/common/parse.rs`.
- [ ] **`SharedTextInterner` + `extract_argument_texts` + `record_call_fact` + `record_assignment_fact`** — duplicated between `cwe/facts.rs` and `perf/facts.rs` (perf variant adds `enclosing_loop`). This is a meaningful refactor and is out of scope here.

---

## Phase 1.24: Recommended order of operations

- [ ] **§1.11, 1.12, 1.13** — already small; no work.
- [ ] **§1.17 `cwe/catalog`** — small, low risk.
- [ ] **§1.15, 1.16, 1.9, 1.10, 1.7, 1.8, 1.6, 1.5, 1.4, 1.1, 1.2, 1.3** — engine files in order of increasing size, smallest first.
- [ ] **§1.14 `ast/function`** — optional, only if the 2 000-char target is strict.
- [ ] **§1.22 `cwe/facts`** — the `pub(crate)` items feed `lang/go/detectors/facts.rs`.
- [ ] **§1.19, 1.20, 1.21, 1.18 `taint/*`** — most cross-referenced; do last so all consumers see stable signatures.
- [ ] **Verification after each batch:** `cargo build --features go && cargo test --lib --features go`

---

## Phase 1.25: Compatibility audit (no test changes required)

The following tests/benches consume only the re-exports at the parent `mod.rs` level. After the split, every public symbol remains reachable at the same path. **No test or bench source file requires modification.**

- [ ] `tests/engine_cache.rs` — `Analyzer, CacheEntry, CacheStore, DEFAULT_CACHE_DIR, Registry, SlopguardConfig, content_hash, discover_cache_dir, go_module_prefix, CACHE_VERSION, extract_dependencies, discover_project_root` (all via `slopguard::engine::*`)
- [ ] `tests/engine_baseline.rs` — `BASELINE_FILE_NAME, Baseline, discover_baseline`
- [ ] `tests/engine_config.rs` — `BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection, build_scan_context, discover_cache_dir, discover_config, fail_on_to_policy, load_discovered_config`
- [ ] `tests/engine_ignore.rs` — `IgnoreDirective, parse_file_ignore, parse_inline_ignores`
- [ ] `tests/engine_observability.rs` — `Analyzer, Diagnostics, ScanStats, TimingCollector`
- [ ] `tests/engine_result.rs` — `AnalysisResult, ScanError, ScanErrorKind`
- [ ] `tests/engine_source_cache.rs` — `Analyzer`
- [ ] `tests/cwe_catalog.rs` — `CWE_CATALOG, CWE_REFS_*, builtin_rule_catalogue, default_ruleset_path`
- [ ] `tests/lang_go_cwe_metadata.rs` — `builtin_rule_catalogue`
- [ ] `tests/lang_go_detectors_cwe_facts.rs` — wildcard import `crate::lang::go::detectors::cwe::facts::*`
- [ ] `benches/scan_throughput.rs` — `Analyzer, LanguageFilter, Registry, collect_entries, ScanContext`
- [ ] `benches/incremental_scan.rs` — `Analyzer, CacheStore, collect_entries, content_hash, LanguageFilter, Registry, ScanContext`
- [ ] Detectors (CWE) — `crate::engine::scratch_contains` (still re-exported from `walk::scratch`)

---

## Phase 1 verification

- [ ] After every batch: `cargo build --features go && cargo test --lib --features go`
- [ ] Final, after all engine + cwe + taint splits: run the full Phase 1 test list from `verification.md` § "Phase 1 (Engine / AST / Core / CWE / taint)"
- [ ] Canary: the wildcard import in `tests/lang_go_detectors_cwe_facts.rs:10` (`use slopguard::lang::go::detectors::cwe::facts::*;`) catches any missing `pub use` re-export in §1.22.

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none.
- **Cross-cutting concerns:**
  - Phase 1's `taint/*` is the most cross-referenced area; `cwe/facts.rs` and `cwe/taint/*` are de-facto in-scope for both Phase 1 and Phase 3. Do the engine side first, then the taint side, then the detector side.
  - The `pub use` re-export in every new `mod.rs` is what keeps the integration tests in Phase 3 (specifically `tests/go_cwe_detector_integration.rs`) green. Forgetting one is caught by the canary.
  - `engine/walk/scratch.rs` exports `scratch_contains` which is consumed by many detector files; the path through `crate::engine::scratch_contains` must remain intact.
