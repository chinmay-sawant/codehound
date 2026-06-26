# Phase 1 — Engine / AST / Core / CWE

**Scope:** `src/engine/`, `src/ast/`, `src/core/`, `src/cwe/`,
`src/lang/go/detectors/cwe/taint/`, `src/lang/go/detectors/cwe/facts.rs`.

**Files covered:** 22 (12 require splitting, 10 are unchanged or optional).

**New files:** ~80.

## 1.0 Module-pattern reference

| Pattern | Where | Implication |
|---|---|---|
| `mod foo;` + `pub use foo::{…};` in parent `mod.rs` | `engine/mod.rs`, `ast/mod.rs`, `core/mod.rs`, `cwe/mod.rs`, `taint/mod.rs` | After a split, the same `mod foo;` line still resolves to either a file or a folder. Add the new `pub use` in the new `foo/mod.rs`. |
| `pub mod foo;` | only `engine/sinks;` (deliberate exception) and `cwe::common` | The new sub-modules stay private; `pub use` in the new `mod.rs` re-exports the public surface. |
| `include!(concat!(env!("OUT_DIR"), "/foo.rs"))` | `src/cwe/catalog.rs`, `src/lang/go/detectors/cwe/metadata.rs`, etc. | The file containing the `include!` is load-bearing. Splits must keep the `include!` directive in the file that owns the corresponding `pub(super) const` items. |

For consistency with the rest of the codebase, every new sub-module
declared by a `mod.rs` is **private**; the public surface is re-exported
with `pub use`.

## 1.1 `src/engine/walk.rs` → `src/engine/walk/`

**Current size:** 27 909 chars / 786 lines.

**Top-level items:** `ScanEntry`, `collect_entries`, `RootPathMatcher`,
`build_globset`, `scan_entry`, `attach_function_context`,
`analyze_parsed_unit`, `analyze_parsed_unit_with_context`, `ScanOutcome`,
`scan_entries_parallel`, `filter_cached_findings`, `mtime_of`,
`bytecount_lines`, `panic_message`, `scratch_contains`.

**External re-exports in `engine/mod.rs`:** `analyze_parsed_unit`,
`analyze_parsed_unit_with_context`, `collect_entries`, `scratch_contains`.

**External users (verified):** `src/app.rs:12`, `benches/scan_throughput.rs:8`,
`benches/incremental_scan.rs:23`, and many detector files via
`crate::engine::scratch_contains`.

**Proposed split (under `src/engine/walk/`):**

| New file | Contents | Approx chars |
|---|---|---:|
| `walk/mod.rs` | `mod` declarations + `pub use {collect_entries, scratch_contains, analyze_parsed_unit, analyze_parsed_unit_with_context};` | ~200 |
| `walk/entry.rs` | `pub struct ScanEntry` + `pub fn collect_entries` + `struct RootPathMatcher` + `fn build_globset` | ~4 500 |
| `walk/parallel.rs` | `pub enum ScanOutcome` + `pub fn scan_entries_parallel` + `fn filter_cached_findings` + `fn mtime_of` + `fn bytecount_lines` + `fn panic_message` | ~7 500 |
| `walk/scan_entry.rs` | `pub fn scan_entry` + `fn attach_function_context` | ~6 500 |
| `walk/analyze.rs` | `pub fn analyze_parsed_unit` + `pub fn analyze_parsed_unit_with_context` | ~2 000 |
| `walk/scratch.rs` | `pub fn scratch_contains` + its `thread_local!` buffer | ~1 200 |

**`mod.rs` changes:** Replace the existing `mod walk; pub use walk::{…};`
in `engine/mod.rs` with `mod walk;` (the new `walk/mod.rs` re-exports
the public surface).

**Compatibility notes:**
- `scan_entry`, `scan_entries_parallel`, `ScanEntry`, `ScanOutcome` are
  not currently re-exported at the engine level. They become
  `pub(crate)` (or stay reachable at `crate::engine::walk::…`).
- No test or bench edits required.

## 1.2 `src/engine/cache.rs` → `src/engine/cache/`

**Current size:** 24 711 chars / 698 lines.

**Top-level items:** `CACHE_VERSION`, `DEFAULT_CACHE_DIR`,
`CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`,
`CacheLookup`, `CacheError`, `MANIFEST_NAME`, `METADATA_NAME`,
`FILES_SUBDIR`, `pub struct CacheStore` + 18 methods + `Drop`,
`content_hash`, `cache_key_for_path`, `hex_lower`, `mtime_of_file`,
`write_atomic`, `iso8601_now`, `iso8601_utc_now`, `iso8601_from_mtime`,
`iso8601_from_secs`, `unix_epoch_to_ymdhms`, `#[cfg(test)] mod tests`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `cache/mod.rs` | `mod` declarations + `pub use` re-exports for every currently-public item. | ~700 |
| `cache/types.rs` | `CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`, `CacheLookup`, `CacheError`, constants. | ~2 800 |
| `cache/hash.rs` | `content_hash`, `cache_key_for_path`, `hex_lower`, `iso8601_now` + private ISO-8601 helpers. | ~2 200 |
| `cache/io.rs` | `mtime_of_file`, `write_atomic`. | ~1 100 |
| `cache/store.rs` | `pub struct CacheStore` + 18 methods + `Drop`. | ~13 000 |
| `cache/tests.rs` | `#[cfg(test)] mod tests` (3 tests). | ~1 200 |

**Optional further split of `store.rs`** if ~13 000 chars is too large:
- `cache/store_open.rs` (constructor, accessors, manifest)
- `cache/store_lifecycle.rs` (`put`, `remove`, `prune`, `clean_orphans`, `invalidate_*`)
- `cache/store_flush.rs` (`flush` + `evict_to_size`)

**`mod.rs` changes:** Replace `mod cache; pub use cache::{…};` with
`mod cache;`. The new `cache/mod.rs` re-exports the entire public
surface.

**Compatibility notes:**
- Internal users `walk.rs` and `analyzer.rs` continue to write
  `crate::engine::cache::…` (path unchanged).
- `Drop for CacheStore` stays in `store.rs`.
- `evict_to_size` calls `self.read_entry` (private). Keep it in
  `store.rs` to avoid making the helper `pub(crate)`.

## 1.3 `src/engine/dependencies.rs` → `src/engine/dependencies/`

**Current size:** 21 005 chars / 609 lines.

**Top-level items:** `extensions_for`, `extract_dependencies`,
`go_module_prefix`, `discover_project_root`, inner `mod go {…}` and
`mod python {…}`, shared `resolve_local_path` / `visit_dir`,
`#[cfg(test)] mod tests`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `dependencies/mod.rs` | `mod` decls + `pub use {discover_project_root, extract_dependencies, go_module_prefix};` | ~250 |
| `dependencies/entry.rs` | `pub fn extract_dependencies` + `fn extensions_for` (language-dispatch). | ~3 500 |
| `dependencies/go_module.rs` | `pub fn go_module_prefix`. | ~700 |
| `dependencies/project_root.rs` | `pub fn discover_project_root`. | ~1 200 |
| `dependencies/go_imports.rs` | the entire `mod go {…}` block. | ~5 800 |
| `dependencies/python_imports.rs` | the entire `mod python {…}` block. | ~6 800 |
| `dependencies/resolve.rs` | shared `resolve_local_path` + `visit_dir` (now `pub(super) fn`). | ~1 800 |
| `dependencies/tests.rs` | `#[cfg(test)] mod tests` + `tempfile_root` helper. | ~1 100 |

**`mod.rs` changes:** `mod dependencies; pub use dependencies::{…};` →
`mod dependencies;` (re-exports move into new `dependencies/mod.rs`).

**Compatibility notes:**
- `extensions_for` moves into `resolve.rs` as `pub(super) fn`; the
  internal Go and Python modules adjust to
  `use super::super::resolve::extensions_for;`.

## 1.4 `src/engine/config.rs` → `src/engine/config/`

**Current size:** 9 209 chars / 326 lines.

**Top-level items:** `SlopguardConfig`, `SlopguardSection`, `BaselineConfig`,
`CacheConfig`, `TaintConfig`, `BadPracticesConfig`, `PathFilters`, the
~17-method `impl SlopguardConfig`, `discover_cache_dir`,
`fail_on_to_policy`, `discover_config`, `load_discovered_config`,
`build_scan_context`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `config/mod.rs` | `mod` decls + `pub use` for all 10 currently re-exported items. | ~500 |
| `config/types.rs` | All `#[derive(Deserialize)]` structs + their `Default` impls. | ~3 500 |
| `config/section.rs` | `impl SlopguardConfig` (the ~17 accessors + `load` + `discover` + `merge_into`). | ~4 200 |
| `config/discover.rs` | `discover_cache_dir`, `discover_config`, `load_discovered_config`, `fail_on_to_policy`. | ~1 600 |
| `config/scan_context.rs` | `build_scan_context`. | ~1 300 |

## 1.5 `src/engine/analyzer.rs` → `src/engine/analyzer/`

**Current size:** 8 773 chars / 264 lines.

**Top-level items:** `AnalyzerBuilder`, `Analyzer`, `sort_findings`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `analyzer/mod.rs` | `mod` decls + `pub use {Analyzer, AnalyzerBuilder};` | ~150 |
| `analyzer/types.rs` | struct definitions + builder accessors. | ~3 000 |
| `analyzer/scan.rs` | `Analyzer::analyze_paths` + cascade-invalidation / pruning. | ~4 800 |
| `analyzer/units.rs` | `Analyzer::analyze_units` + `sort_findings`. | ~1 500 |

## 1.6 `src/engine/timing.rs` → `src/engine/timing/`

**Current size:** 6 870 chars / 227 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `timing/mod.rs` | `mod` decls + `pub use {PhaseTiming, TimingCollector, TimingSpan, TimingSummary};` | ~250 |
| `timing/collector.rs` | `TimingSpan`, `TimingCollector` + impl. | ~3 500 |
| `timing/summary.rs` | `TimingSummary` + impl + `PhaseTiming`. | ~3 000 |
| `timing/serde.rs` | `mod duration_millis` helper. | ~700 |
| `timing/tests.rs` | `#[cfg(test)] mod tests` (3 tests). | ~1 100 |

## 1.7 `src/engine/baseline.rs` → `src/engine/baseline/`

**Current size:** 6 463 chars / 201 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `baseline/mod.rs` | `mod` decls + `pub use {BASELINE_FILE_NAME, BASELINE_VERSION, Baseline, BaselineEntry, discover_baseline};` | ~250 |
| `baseline/entry.rs` | `BaselineEntry` + private `BaselineLocationKey`. | ~700 |
| `baseline/store.rs` | `Baseline` + its 7-method impl. | ~3 500 |
| `baseline/io.rs` | `discover_baseline` + duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms`. | ~1 800 |

## 1.8 `src/engine/diagnostics.rs` → `src/engine/diagnostics/`

**Current size:** 5 469 chars / 172 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `diagnostics/mod.rs` | `mod` decls + `pub use {Diagnostics, ScanDiagnostics, FindingsDiagnostics, TimingDiagnostics, DetectorsDiagnostics, RuleTiming};` | ~250 |
| `diagnostics/types.rs` | The five `#[derive(Serialize)]` sub-structs. | ~1 800 |
| `diagnostics/build.rs` | `pub struct Diagnostics` + `impl Diagnostics::from_stats`. | ~2 800 |
| `diagnostics/clock.rs` | The duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms`. | ~1 100 |

## 1.9 `src/engine/stats.rs` → `src/engine/stats/`

**Current size:** 4 745 chars / 146 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `stats/mod.rs` | `mod` decls + `pub use {FileStats, ScanStats};` | ~150 |
| `stats/scan.rs` | `ScanStats` + `impl`. | ~3 200 |
| `stats/file.rs` | `FileStats` + `impl`. | ~1 000 |

## 1.10 `src/engine/ignore.rs` → `src/engine/ignore/`

**Current size:** 4 579 chars / 183 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `ignore/mod.rs` | `mod` decls + `pub use {IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore, parse_inline_ignores};` | ~250 |
| `ignore/directive.rs` | `IgnoreDirective` + its impl. | ~900 |
| `ignore/parse.rs` | `parse_inline_ignores`, `parse_file_ignore`, private helpers. | ~2 000 |
| `ignore/apply.rs` | `apply_inline_ignores`, `apply_file_ignore`, `apply_directive`. | ~1 700 |

## 1.11 `src/engine/registry.rs`

**Current size:** 2 885 chars / 95 lines. **No split** — single
`impl Registry` block, already under the 3 000-char ceiling.

## 1.12 `src/engine/result.rs`

**Current size:** 2 774 chars / 87 lines. **No split.**

## 1.13 `src/engine/language_filter.rs`

**Current size:** 2 302 chars / 75 lines. **No split.**

## 1.14 `src/ast/function.rs` (optional)

**Current size:** 3 366 chars / 102 lines.

Slightly over the 3 000 ceiling but tight. **Recommendation: leave as-is.**

If a split is required: `ast/function/span.rs` (~1 500) +
`ast/function/collect.rs` (~1 700).

## 1.15 `src/core/scan.rs` → `src/core/scan/`

**Current size:** 3 523 chars / 117 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `scan/mod.rs` | `mod` decls + `pub use {FailPolicy, ScanContext};` | ~150 |
| `scan/policy.rs` | `pub enum FailPolicy` + impl. | ~700 |
| `scan/context.rs` | `pub struct ScanContext` + `Default` + impl. | ~2 500 |
| `scan/filter.rs` | private `fn rule_matches`. | ~400 |

## 1.16 `src/core/language.rs` → `src/core/language/`

**Current size:** 3 255 chars / 99 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `language/mod.rs` | `mod` decls + `pub use {LanguageId, LanguagePlugin};` | ~150 |
| `language/id.rs` | `LanguageId` + impl. | ~1 800 |
| `language/plugin.rs` | `trait LanguagePlugin`. | ~1 600 |

## 1.17 `src/cwe/catalog.rs` → `src/cwe/catalog/`

**Current size:** 3 899 chars / 112 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `catalog/mod.rs` | `mod` decls + `pub use` of all 8 currently re-exported items. | ~500 |
| `catalog/consts.rs` | The 6 hand-written `CWE_*` consts + `CWE_CATALOG` + `CWE_REFS_*` slices + `include!(.../cwe_catalog_generated.rs)`. | ~1 700 |
| `catalog/description.rs` | `RuleDescription` + `load_rule_descriptions` + `default_ruleset_path` + `include!(.../rule_catalogue.rs)` + the `deserialize_id` helper. | ~1 900 |

**Caveat:** The two `include!` directives are textual inclusions of
build-script output. Both must stay in the same file that owns the
corresponding generated `pub static`/`pub fn` items.

## 1.18 `src/lang/go/detectors/cwe/taint/mod.rs` → `taint/`

**Current size:** 7 720 chars / 245 lines.

**Special:** This file is the public entry of the taint subsystem. The
existing children (`extract.rs`, `graph.rs`, `rules.rs`) are large and
also need splitting (see §1.19–1.21). After the children are split, this
`mod.rs` becomes a thin re-exporter.

**Proposed new `taint/mod.rs`:**

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

**Rename:** `taint/graph.rs` → `taint/graph_query.rs` to free the name
`graph` for the new data-model file. Update `taint/mod.rs` to
`pub mod graph_query;` and re-export from there.

## 1.19 `src/lang/go/detectors/cwe/taint/extract.rs` → `extract/`

**Current size:** 16 609 chars / 549 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `extract/mod.rs` | `mod` decls + `pub use {extract_taint_facts};` | ~300 |
| `extract/walker_core.rs` | `extract_taint_facts` + `ExtractionState` + `walk_node` + `is_chained_call`. | ~3 500 |
| `extract/walker_records.rs` | `record_call` + `record_assignment` + `result_variable_of_call` + `argument_texts`. | ~3 200 |
| `extract/classify.rs` | `classify_source` + `classify_sink` + `classify_sanitizer` + `receiver_of_method_call` + `is_template_html_call` + `is_source_or_sanitizer_call`. | ~3 700 |
| `extract/assignments.rs` | `split_assignment` + `extract_identifiers`. | ~700 |
| `extract/tests.rs` | `#[cfg(test)] mod tests` (4 tests). | ~2 500 |

## 1.20 `src/lang/go/detectors/cwe/taint/graph.rs` → `graph_query/`

**Current size:** 13 275 chars / 418 lines.

**Proposed split** (after rename to `graph_query.rs` per §1.18):

| New file | Contents | Approx chars |
|---|---|---:|
| `graph_query/mod.rs` | `mod` decls + `pub use {TaintPath, build_taint_graph, find_taint_paths};` | ~250 |
| `graph_query/build.rs` | `build_taint_graph` + `wire_arguments` + `resolve_variable` + `referenced_identifiers` + `is_go_keyword` + `as_simple_identifier`. | ~4 800 |
| `graph_query/query.rs` | `TaintPath` + `find_taint_paths` + `bfs_path` + `is_sanitizer`. | ~4 000 |
| `graph_query/tests.rs` | `#[cfg(test)] mod tests` (4 tests). | ~3 000 |

## 1.21 `src/lang/go/detectors/cwe/taint/rules.rs` → `rules/`

**Current size:** 7 231 chars / 237 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `rules/mod.rs` | `mod` decls + `pub use {detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint};` | ~300 |
| `rules/cwe_22.rs` | `detect_cwe_22_taint`. | ~2 000 |
| `rules/cwe_78.rs` | `detect_cwe_78_taint`. | ~1 900 |
| `rules/cwe_79.rs` | `detect_cwe_79_taint`. | ~1 900 |
| `rules/cwe_89.rs` | `detect_cwe_89_taint`. | ~1 500 |
| `rules/evidence.rs` | `variable_name_at` + `source_info`. | ~700 |

## 1.22 `src/lang/go/detectors/cwe/facts.rs` → `facts/`

**Current size:** 6 093 chars / 215 lines.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `facts/mod.rs` | `mod` decls + `pub use` of public types + public helpers. | ~500 |
| `facts/types.rs` | `InputKind`, `InputBinding`, `CallFact`, `AssignmentFact`, `GoUnitFacts`. | ~1 700 |
| `facts/build.rs` | `build_go_unit_facts` + `build_taint_graph_for_facts`. | ~1 500 |
| `facts/interner.rs` | `SharedTextInterner` + impl + `extract_argument_texts` + `record_call_fact` + `record_assignment_fact` (all `pub(crate)`). | ~2 000 |
| `facts/expr_patterns.rs` | `split_assignment` + `extract_identifiers` + `is_user_input_expr` + `is_trusted_config_expr`. | ~1 200 |

**Caveat:** `lang/go/detectors/facts.rs:2-7` aliases
`SharedTextInterner as CweInterner`, `record_call_fact as record_cwe_call`,
`record_assignment_fact as record_cwe_assign`. After the split, those
become `crate::lang::go::detectors::cwe::facts::interner::{…}` but
must remain `pub(crate) use` re-exported from `facts/mod.rs`.

## 1.23 Duplicates flagged for de-duplication

These are not in the strict scope of the split but are removed as a
side-effect:

1. **`iso8601_utc_now` + `unix_epoch_to_ymdhms`** — duplicated across
   `cache.rs`, `baseline.rs`, `diagnostics.rs`, `reporting/sarif.rs`.
   The split moves each copy to its per-file `clock.rs` (or
   `time.rs`). A future cleanup would extract them into a single
   `engine/time.rs` (~120 lines saved).

2. **`split_assignment` + `extract_identifiers`** — duplicated across
   `cwe/facts.rs`, `cwe/taint/extract.rs`, `perf/facts.rs`. A future
   cleanup would move them to a single `lang/go/detectors/common/parse.rs`.

3. **`SharedTextInterner` + `extract_argument_texts` + `record_call_fact`
   + `record_assignment_fact`** — duplicated between `cwe/facts.rs` and
   `perf/facts.rs` (perf variant adds `enclosing_loop`). This is a
   meaningful refactor and is out of scope here.

## 1.24 Recommended order of operations

1. **§1.11, 1.12, 1.13** — already small; no work.
2. **§1.17 `cwe/catalog`** — small, low risk.
3. **§1.15, 1.16, 1.9, 1.10, 1.7, 1.8, 1.6, 1.5, 1.4, 1.1, 1.2, 1.3** — engine files in order of increasing size, smallest first.
4. **§1.14 `ast/function`** — optional, only if the 2 000-char target is strict.
5. **§1.22 `cwe/facts`** — the `pub(crate)` items feed `lang/go/detectors/facts.rs`.
6. **§1.19, 1.20, 1.21, 1.18 `taint/*`** — most cross-referenced; do last so all consumers see stable signatures.
7. **Verification after each batch:** `cargo build --features go && cargo test --lib --features go`.

## 1.25 Compatibility audit (no test changes required)

The following tests/benches consume only the re-exports at the parent
`mod.rs` level. After the split, every public symbol remains reachable
at the same path. **No test or bench source file requires modification.**

| File | What it imports |
|---|---|
| `tests/engine_cache.rs` | `Analyzer, CacheEntry, CacheStore, DEFAULT_CACHE_DIR, Registry, SlopguardConfig, content_hash, discover_cache_dir, go_module_prefix, CACHE_VERSION, extract_dependencies, discover_project_root` (all via `slopguard::engine::*`) |
| `tests/engine_baseline.rs` | `BASELINE_FILE_NAME, Baseline, discover_baseline` |
| `tests/engine_config.rs` | `BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection, build_scan_context, discover_cache_dir, discover_config, fail_on_to_policy, load_discovered_config` |
| `tests/engine_ignore.rs` | `IgnoreDirective, parse_file_ignore, parse_inline_ignores` |
| `tests/engine_observability.rs` | `Analyzer, Diagnostics, ScanStats, TimingCollector` |
| `tests/engine_result.rs` | `AnalysisResult, ScanError, ScanErrorKind` |
| `tests/engine_source_cache.rs` | `Analyzer` |
| `tests/cwe_catalog.rs` | `CWE_CATALOG, CWE_REFS_*, builtin_rule_catalogue, default_ruleset_path` |
| `tests/lang_go_cwe_metadata.rs` | `builtin_rule_catalogue` |
| `tests/lang_go_detectors_cwe_facts.rs` | wildcard import `crate::lang::go::detectors::cwe::facts::*` |
| `benches/scan_throughput.rs` | `Analyzer, LanguageFilter, Registry, collect_entries, ScanContext` |
| `benches/incremental_scan.rs` | `Analyzer, CacheStore, collect_entries, content_hash, LanguageFilter, Registry, ScanContext` |
| Detectors (CWE) | `crate::engine::scratch_contains` (still re-exported from `walk::scratch`) |
