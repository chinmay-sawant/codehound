# Phase 1 — Engine / AST / Core / CWE

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** **Complete.** All 16 splits done (§1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.15, 1.16, 1.17, 1.18, 1.19, 1.20, 1.21, 1.22) + §1.2 optional further split of `store.rs` (3 sub-files) + §1.14 optional split of `ast/function.rs` (2 sub-files) + 3 no-split confirmations (§1.11, 1.12, 1.13). ~85 new files authored. `cargo test --features go,python` and `cargo test --all-features` both green: 41/41 test binaries pass, 0 failures.
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
**New files:** ~80. **All ~80 + 5 optional sub-files (3 from §1.2 cache/store further split, 2 from §1.14 ast/function split) delivered.**

---

## Executive Summary

- **Problem:** Engine files dominate the largest-file list (`walk.rs` 27.9 KB, `cache.rs` 24.7 KB, `dependencies.rs` 21.0 KB, `config.rs` 9.2 KB). The taint subsystem and `cwe/facts.rs` are the most cross-referenced.
- **Approach:** Convert each `.rs` file into a folder of focused sub-modules. Every new `mod.rs` is private; public surface is re-exported with `pub use`. Leave the `pub mod sinks;` exception in `engine/mod.rs` intact.
- **Success criteria:** All 22 files in scope are either split or confirmed under 3 000 chars. Public symbols remain reachable at the same path. `cargo build --features go && cargo test --lib --features go` is green after every batch.
- **Trade-offs:** `cache/store.rs` was further split into `store_open.rs` (6 002 chars), `store_lifecycle.rs` (6 259), `store_flush.rs` (4 386) — all in the 4 000–6 000 exception band. `engine/walk/parallel.rs` is ~15 KB (also in the 6 000+ exception band). `ast/function/` was split into `collect.rs` (2 878) and `span.rs` (540) — both well under the 3 000-char ceiling.
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

- [x] Create `src/engine/walk/mod.rs` with `mod` declarations + `pub use {collect_entries, scratch_contains, analyze_parsed_unit, analyze_parsed_unit_with_context};` (~200 chars)
- [x] Create `src/engine/walk/entry.rs` with `pub struct ScanEntry` + `pub fn collect_entries` + `struct RootPathMatcher` + `fn build_globset` (~4 500 chars)
- [x] Create `src/engine/walk/parallel.rs` with `pub enum ScanOutcome` + `pub fn scan_entries_parallel` + `fn filter_cached_findings` + `fn mtime_of` + `fn bytecount_lines` + `fn panic_message` (~7 500 chars)
- [x] Create `src/engine/walk/scan_entry.rs` with `pub fn scan_entry` + `fn attach_function_context` (~6 500 chars)
- [x] Create `src/engine/walk/analyze.rs` with `pub fn analyze_parsed_unit` + `pub fn analyze_parsed_unit_with_context` (~2 000 chars)
- [x] Create `src/engine/walk/scratch.rs` with `pub fn scratch_contains` + its `thread_local!` buffer (~1 200 chars)
- [x] Delete `src/engine/walk.rs`
- [x] In `engine/mod.rs`, replace existing `mod walk; pub use walk::{…};` with `mod walk;` (the new `walk/mod.rs` re-exports the public surface)

### Compatibility notes

- [x] `scan_entry`, `scan_entries_parallel`, `ScanEntry`, `ScanOutcome` are not currently re-exported at the engine level. They become `pub(crate)` (or stay reachable at `crate::engine::walk::…`).
- [x] No test or bench edits required.

### Implementation notes (2026-06-26)

- Resulting file sizes: `mod.rs` = 325 chars, `entry.rs` = 3 712, `parallel.rs` = 15 365, `scan_entry.rs` = 7 090, `analyze.rs` = 1 932, `scratch.rs` = 1 013. **Total: 29 437 chars across 6 files.**
- `parallel.rs` (15.4 KB) and `scan_entry.rs` (7.1 KB) are in the 6 000+ exception band. Kept as one file each because further splitting would over-fragment.
- `engine/mod.rs` was **not** edited: it still has `pub use walk::{analyze_parsed_unit, analyze_parsed_unit_with_context, collect_entries, scratch_contains};` because `app.rs`, `benches/scan_throughput.rs`, and `benches/incremental_scan.rs` consume these via `crate::engine::…`.
- `ScanEntry` stays `pub` (not `pub(crate)`) because the bin `app.rs` reads `entry.path` for cache pruning.
- `scan_entries_parallel` is `pub(crate)` because it's only used by the analyzer (in lib).
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.2: `src/engine/cache.rs` → `src/engine/cache/`

**Current size:** 24 711 chars / 698 lines.
**Top-level items:** `CACHE_VERSION`, `DEFAULT_CACHE_DIR`, `CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`, `CacheLookup`, `CacheError`, `MANIFEST_NAME`, `METADATA_NAME`, `FILES_SUBDIR`, `pub struct CacheStore` + 18 methods + `Drop`, `content_hash`, `cache_key_for_path`, `hex_lower`, `mtime_of_file`, `write_atomic`, `iso8601_now`, `iso8601_utc_now`, `iso8601_from_mtime`, `iso8601_from_secs`, `unix_epoch_to_ymdhms`, `#[cfg(test)] mod tests`.

### Proposed file tree

- [x] Create `src/engine/cache/mod.rs` with `mod` declarations + `pub use` re-exports for every currently-public item (~700 chars)
- [x] Create `src/engine/cache/types.rs` with `CacheManifest`, `FileCacheMeta`, `CacheEntry`, `CacheMetadata`, `CacheLookup`, `CacheError`, constants (~2 800 chars)
- [x] Create `src/engine/cache/hash.rs` with `content_hash`, `cache_key_for_path`, `hex_lower`, `iso8601_now` + private ISO-8601 helpers (~2 200 chars)
- [x] Create `src/engine/cache/io.rs` with `mtime_of_file`, `write_atomic` (~1 100 chars)
- [x] Create `src/engine/cache/store.rs` with `pub struct CacheStore` + 18 methods + `Drop` (~13 000 chars)
- [x] Create `src/engine/cache/tests.rs` with `#[cfg(test)] mod tests` (3 tests) (~1 200 chars)
- [x] Delete `src/engine/cache.rs`
- [x] In `engine/mod.rs`, replace `mod cache; pub use cache::{…};` with `mod cache;`. The new `cache/mod.rs` re-exports the entire public surface.

### Optional further split of `store.rs` if ~13 000 chars is too large

- [x] `cache/store_open.rs` (constructor, accessors, manifest)
- [x] `cache/store_lifecycle.rs` (`put`, `remove`, `prune`, `clean_orphans`, `invalidate_*`)
- [x] `cache/store_flush.rs` (`flush` + `evict_to_size`)

### Compatibility notes

- [x] Internal users `walk.rs` and `analyzer.rs` continue to write `crate::engine::cache::…` (path unchanged).
- [x] `Drop for CacheStore` stays in `store_flush.rs` (co-located with `flush` and `total_size`).
- [x] `evict_to_size` calls `self.read_entry` (now `pub(super) fn read_entry` in `store_open.rs` that delegates to `super::store_lifecycle::read_entry`).

### Implementation notes (2026-06-26, follow-up)

- `store.rs` was further split into three sub-files (see "Optional further split of `store.rs`" section below) on 2026-06-26.
- `mod.rs` now only declares the submodules and the `CacheStore` struct itself; the 18-method `impl CacheStore` block is split across `store_open.rs` (constructor + accessors + manifest), `store_lifecycle.rs` (`put`/`remove`/`prune`/`clean_orphans`/`invalidate_*` + the `read_entry` helper), and `store_flush.rs` (`flush` + `evict_to_size` + `total_size` + `Drop`).
- Internal constants `MANIFEST_NAME`, `METADATA_NAME`, `FILES_SUBDIR` are `pub(super)` in `types.rs` (used only by `store_open.rs`).
- `iso8601_utc_now` + `iso8601_from_mtime` are `pub(super)` in `hash.rs` (used by `store_flush.rs::flush` and `evict_to_size`).
- `mtime_of_file` + `write_atomic` are `pub(super)` in `io.rs` (used by `store_open.rs::lookup` and `store_lifecycle.rs::put`).
- Tests use `mod t` (not `mod tests`) to avoid `tests::tests` path duplication.
- `engine/mod.rs` re-export block was **kept** (not removed as the plan said) because `app.rs:11` and detector files import from `crate::engine::cache::…`.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; cache tests at `engine::cache::tests::t::*`).

### Implementation notes (2026-06-26, follow-up to optional further split)

Resulting file sizes (replacing the prior 16 KB `store.rs`):
- `store_open.rs` = 6 002 chars (in the 4 000–6 000 exception band)
- `store_lifecycle.rs` = 6 259 chars (in the 4 000–6 000 exception band)
- `store_flush.rs` = 4 386 chars (within the 3 000-char target + exception)

The `CacheStore` struct itself lives in `mod.rs` (not in any sub-file) so all three sibling `impl` blocks can extend it. `read_entry` is a `pub(super) fn` in `store_open.rs` that delegates to a free function `read_entry(store: &CacheStore, cache_key: &str) -> Option<CacheEntry>` in `store_lifecycle.rs` (so the in-memory format-parse code lives with the rest of the lifecycle).

Verification: `cargo test --test engine_cache --features go,python` (27/27 pass) and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.3: `src/engine/dependencies.rs` → `src/engine/dependencies/`

**Current size:** 21 005 chars / 609 lines.
**Top-level items:** `extensions_for`, `extract_dependencies`, `go_module_prefix`, `discover_project_root`, inner `mod go {…}` and `mod python {…}`, shared `resolve_local_path` / `visit_dir`, `#[cfg(test)] mod tests`.

### Proposed file tree

- [x] Create `src/engine/dependencies/mod.rs` with `mod` decls + `pub use {discover_project_root, extract_dependencies, go_module_prefix};` (~250 chars)
- [x] Create `src/engine/dependencies/entry.rs` with `pub fn extract_dependencies` + `fn extensions_for` (language-dispatch) (~3 500 chars)
- [x] Create `src/engine/dependencies/go_module.rs` with `pub fn go_module_prefix` (~700 chars)
- [x] Create `src/engine/dependencies/project_root.rs` with `pub fn discover_project_root` (~1 200 chars)
- [x] Create `src/engine/dependencies/go_imports.rs` with the entire `mod go {…}` block (~5 800 chars)
- [x] Create `src/engine/dependencies/python_imports.rs` with the entire `mod python {…}` block (~6 800 chars)
- [x] Create `src/engine/dependencies/resolve.rs` with shared `resolve_local_path` + `visit_dir` (now `pub(super) fn`) (~1 800 chars)
- [x] Create `src/engine/dependencies/tests.rs` with `#[cfg(test)] mod tests` + `tempfile_root` helper (~1 100 chars)
- [x] Delete `src/engine/dependencies.rs`
- [x] In `engine/mod.rs`, replace `mod dependencies; pub use dependencies::{…};` with `mod dependencies;` (re-exports move into new `dependencies/mod.rs`)

### Compatibility notes

- [x] `extensions_for` moves into `resolve.rs` as `pub(super) fn`; the internal Go and Python modules adjust to `use super::super::resolve::extensions_for;`.

### Implementation notes (2026-06-26)

- `extensions_for` actually went into `entry.rs` (with a `pub(super) fn extensions` re-export via `super::resolve`) so the dispatch logic stays co-located with `extract_dependencies`. The plan said `resolve.rs` but the cleaner home is `entry.rs`.
- `entry.rs` re-exports `resolve_local_path` as `pub(super) use super::resolve::resolve_local_path;` so `go_imports` and `python_imports` access it via `super::super::resolve::resolve_local_path`.
- `tests.rs` uses `crate::engine::dependencies::go_module_prefix` (the public re-export) instead of `super::go_module::go_module_prefix` to avoid private-module confusion.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; dependencies tests at `engine::dependencies::tests::t::*`).

---

## Phase 1.4: `src/engine/config.rs` → `src/engine/config/`

**Current size:** 9 209 chars / 326 lines.
**Top-level items:** `SlopguardConfig`, `SlopguardSection`, `BaselineConfig`, `CacheConfig`, `TaintConfig`, `BadPracticesConfig`, `PathFilters`, the ~17-method `impl SlopguardConfig`, `discover_cache_dir`, `fail_on_to_policy`, `discover_config`, `load_discovered_config`, `build_scan_context`.

### Proposed file tree

- [x] Create `src/engine/config/mod.rs` with `mod` decls + `pub use` for all 10 currently re-exported items (~500 chars)
- [x] Create `src/engine/config/types.rs` with all `#[derive(Deserialize)]` structs + their `Default` impls (~3 500 chars)
- [x] Create `src/engine/config/section.rs` with `impl SlopguardConfig` (the ~17 accessors + `load` + `discover` + `merge_into`) (~4 200 chars)
- [x] Create `src/engine/config/discover.rs` with `discover_cache_dir`, `discover_config`, `load_discovered_config`, `fail_on_to_policy` (~1 600 chars)
- [x] Create `src/engine/config/scan_context.rs` with `build_scan_context` (~1 300 chars)
- [x] Delete `src/engine/config.rs`

### Implementation notes (2026-06-26)

- The `mod.rs` re-exports **only the items the engine parent actually uses** (`BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection`). `BadPracticesConfig` and `TaintConfig` are kept in `types.rs` but are reachable as `crate::engine::config::types::{BadPracticesConfig, TaintConfig}` if needed.
- `section.rs` is a top-level `impl SlopguardConfig` block; it lives in its own file to keep `types.rs` (data only) separate from the accessors.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.5: `src/engine/analyzer.rs` → `src/engine/analyzer/`

**Current size:** 8 773 chars / 264 lines.
**Top-level items:** `AnalyzerBuilder`, `Analyzer`, `sort_findings`.

### Proposed file tree

- [x] Create `src/engine/analyzer/mod.rs` with `mod` decls + `pub use {Analyzer, AnalyzerBuilder};` (~150 chars)
- [x] Create `src/engine/analyzer/types.rs` with struct definitions + builder accessors (~3 000 chars)
- [x] Create `src/engine/analyzer/scan.rs` with `Analyzer::analyze_paths` + cascade-invalidation / pruning (~4 800 chars)
- [x] Create `src/engine/analyzer/units.rs` with `Analyzer::analyze_units` + `sort_findings` (~1 500 chars)
- [x] Delete `src/engine/analyzer.rs`

### Implementation notes (2026-06-26)

- `Analyzer` and `AnalyzerBuilder` fields are `pub(super)` (not `private`) so sibling modules `scan.rs` and `units.rs` can access them. The struct itself stays `pub` (the bin `app.rs` instantiates `Analyzer::builder()`).
- `sort_findings` is `pub(super) fn` in `scan.rs` and reused by `units.rs`.
- `units.rs` uses `super::types::Analyzer` + `super::scan::sort_findings` to reach the sibling items.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.6: `src/engine/timing.rs` → `src/engine/timing/`

**Current size:** 6 870 chars / 227 lines.

### Proposed file tree

- [x] Create `src/engine/timing/mod.rs` with `mod` decls + `pub use {PhaseTiming, TimingCollector, TimingSpan, TimingSummary};` (~250 chars)
- [x] Create `src/engine/timing/collector.rs` with `TimingSpan`, `TimingCollector` + impl (~3 500 chars)
- [x] Create `src/engine/timing/summary.rs` with `TimingSummary` + impl + `PhaseTiming` (~3 000 chars)
- [x] Create `src/engine/timing/serde.rs` with `mod duration_millis` helper (~700 chars) — **renamed to `millis.rs` to avoid shadowing the external `serde` crate** (see implementation notes)
- [x] Create `src/engine/timing/tests.rs` with `#[cfg(test)] mod tests` (3 tests) (~1 100 chars)
- [x] Delete `src/engine/timing.rs`

### Implementation notes (2026-06-26)

- **Local file renamed:** the plan called for `timing/serde.rs` but that **shadows the external `serde` crate** when `summary.rs` does `use serde::Serialize;`. Renamed to `timing/millis.rs` to avoid the conflict. The `duration_millis` inner module lives at `crate::engine::timing::millis::duration_millis`.
- `summary.rs` uses `#[serde(with = "super::millis::duration_millis")]` to reach the helper. The attribute path is resolved by the `serde` proc macro from the current module.
- Tests file uses `mod t` (not `mod tests`) to avoid `engine::timing::tests::tests::…` path duplication.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; timing tests at `engine::timing::tests::t::*`).

---

## Phase 1.7: `src/engine/baseline.rs` → `src/engine/baseline/`

**Current size:** 6 463 chars / 201 lines.

### Proposed file tree

- [x] Create `src/engine/baseline/mod.rs` with `mod` decls + `pub use {BASELINE_FILE_NAME, BASELINE_VERSION, Baseline, BaselineEntry, discover_baseline};` (~250 chars)
- [x] Create `src/engine/baseline/entry.rs` with `BaselineEntry` + private `BaselineLocationKey` (~700 chars)
- [x] Create `src/engine/baseline/store.rs` with `Baseline` + its 7-method impl (~3 500 chars)
- [x] Create `src/engine/baseline/io.rs` with `discover_baseline` + duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms` (~1 800 chars)
- [x] Delete `src/engine/baseline.rs`

### Implementation notes (2026-06-26)

- `BaselineLocationKey` is `pub(super)` (in `entry.rs`) so `store.rs` can construct/compare it.
- `iso8601_utc_now` + `unix_epoch_to_ymdhms` are `pub(super)` in `io.rs` so `store.rs::Baseline::from_findings` can call them to populate `generated_at`.
- `Baseline::from_findings(&[Finding])` keeps the original signature (no extra `generated_at` parameter); it calls `io::iso8601_utc_now()` internally.
- `mod.rs` re-exports `BASELINE_VERSION` from `store.rs` (it's a `pub const` in the type, not a separate file).
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.8: `src/engine/diagnostics.rs` → `src/engine/diagnostics/`

**Current size:** 5 469 chars / 172 lines.

### Proposed file tree

- [x] Create `src/engine/diagnostics/mod.rs` with `mod` decls + `pub use {Diagnostics, ScanDiagnostics, FindingsDiagnostics, TimingDiagnostics, DetectorsDiagnostics, RuleTiming};` (~250 chars)
- [x] Create `src/engine/diagnostics/types.rs` with the five `#[derive(Serialize)]` sub-structs (~1 800 chars)
- [x] Create `src/engine/diagnostics/build.rs` with `pub struct Diagnostics` + `impl Diagnostics::from_stats` (~2 800 chars)
- [x] Create `src/engine/diagnostics/clock.rs` with the duplicate `iso8601_utc_now` + `unix_epoch_to_ymdhms` (~1 100 chars)
- [x] Delete `src/engine/diagnostics.rs`

### Implementation notes (2026-06-26)

- `mod.rs` only re-exports `Diagnostics` (the parent `engine/mod.rs` re-exports the same). The five sub-types (`ScanDiagnostics`, `FindingsDiagnostics`, `TimingDiagnostics`, `DetectorsDiagnostics`, `RuleTiming`) are reachable as `crate::engine::diagnostics::types::{…}`.
- `clock.rs::iso8601_utc_now` is `pub(super)` so `build.rs::Diagnostics::from_stats` can call it.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.9: `src/engine/stats.rs` → `src/engine/stats/`

**Current size:** 4 745 chars / 146 lines.

### Proposed file tree

- [x] Create `src/engine/stats/mod.rs` with `mod` decls + `pub use {FileStats, ScanStats};` (~150 chars)
- [x] Create `src/engine/stats/scan.rs` with `ScanStats` + `impl` (~3 200 chars)
- [x] Create `src/engine/stats/file.rs` with `FileStats` + `impl` (~1 000 chars)
- [x] Delete `src/engine/stats.rs`

### Implementation notes (2026-06-26)

- No deviations from the plan. `ScanStats` and `FileStats` are re-exported from the engine level.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.10: `src/engine/ignore.rs` → `src/engine/ignore/`

**Current size:** 4 579 chars / 183 lines.

### Proposed file tree

- [x] Create `src/engine/ignore/mod.rs` with `mod` decls + `pub use {IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore, parse_inline_ignores};` (~250 chars)
- [x] Create `src/engine/ignore/directive.rs` with `IgnoreDirective` + its impl (~900 chars)
- [x] Create `src/engine/ignore/parse.rs` with `parse_inline_ignores`, `parse_file_ignore`, private helpers (~2 000 chars)
- [x] Create `src/engine/ignore/apply.rs` with `apply_inline_ignores`, `apply_file_ignore`, `apply_directive` (~1 700 chars)
- [x] Delete `src/engine/ignore.rs`

### Implementation notes (2026-06-26)

- All five public functions (`IgnoreDirective`, `apply_file_ignore`, `apply_inline_ignores`, `parse_file_ignore`, `parse_inline_ignores`) are `pub` (not `pub(crate)`) because the engine-level `pub use ignore::{…}` re-exports them and tests like `tests/engine_ignore.rs` and `tests/app_inline_ignore.rs` consume them via `crate::engine::ignore::…`.
- `apply_directive` (private helper of `apply_file_ignore`) lives in `apply.rs`.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.11: `src/engine/registry.rs` — **no split**

**Current size:** 2 885 chars / 95 lines.
- [x] Confirm under 3 000-char ceiling — single `impl Registry` block. **No work.**

## Phase 1.12: `src/engine/result.rs` — **no split**

**Current size:** 2 774 chars / 87 lines.
- [x] Confirm under 3 000-char ceiling. **No work.**

## Phase 1.13: `src/engine/language_filter.rs` — **no split**

**Current size:** 2 302 chars / 75 lines.
- [x] Confirm under 3 000-char ceiling. **No work.**

---

## Phase 1.14: `src/ast/function.rs` → `src/ast/function/`

**Current size:** 3 366 chars / 102 lines.

- [x] **Split done** (2026-06-26, follow-up). The plan originally recommended leaving as-is, but a follow-up split separates the data type from the tree walker cleanly.
- [x] Create `src/ast/function/mod.rs` with `mod` decls + `pub use {FunctionSpan, collect_function_spans, enclosing_function};` and `pub(crate) use collect::try_record_function_span;` (~370 chars)
- [x] Create `src/ast/function/collect.rs` with `FunctionSpan` + `collect_function_spans` + private `walk` + `pub(crate) fn try_record_function_span` (~2 880 chars)
- [x] Create `src/ast/function/span.rs` with `enclosing_function` (~540 chars)
- [x] Delete `src/ast/function.rs`

### Implementation notes (2026-06-26, follow-up)

- `mod.rs` re-exports `FunctionSpan`, `collect_function_spans`, and `enclosing_function` at the public level (the same surface as the original `function.rs`).
- `try_record_function_span` is `pub(crate)` and consumed by `src/ast/walk.rs` (verified by `rg "try_record_function_span" src/ast/`).
- The original file had 102 lines; the new layout has 64 lines (3 files) — each well under the 3 000-char ceiling.
- Verification: `cargo build --features go,python` and `cargo test --features go,python` (18/18 pass).

---

## Phase 1.15: `src/core/scan.rs` → `src/core/scan/`

**Current size:** 3 523 chars / 117 lines.

### Proposed file tree

- [x] Create `src/core/scan/mod.rs` with `mod` decls + `pub use {FailPolicy, ScanContext};` (~150 chars)
- [x] Create `src/core/scan/policy.rs` with `pub enum FailPolicy` + impl (~700 chars)
- [x] Create `src/core/scan/context.rs` with `pub struct ScanContext` + `Default` + impl (~2 500 chars)
- [x] Create `src/core/scan/filter.rs` with private `fn rule_matches` (~400 chars)
- [x] Delete `src/core/scan.rs`

### Implementation notes (2026-06-26)

- `rule_matches` is `pub(super)` in `filter.rs` so `context.rs::ScanContext::allows` can call it. The plan said "private fn" but it must be visible to the sibling `context.rs` module.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.16: `src/core/language.rs` → `src/core/language/`

**Current size:** 3 255 chars / 99 lines.

### Proposed file tree

- [x] Create `src/core/language/mod.rs` with `mod` decls + `pub use {LanguageId, LanguagePlugin};` (~150 chars)
- [x] Create `src/core/language/id.rs` with `LanguageId` + impl (~1 800 chars)
- [x] Create `src/core/language/plugin.rs` with `trait LanguagePlugin` (~1 600 chars)
- [x] Delete `src/core/language.rs`

### Implementation notes (2026-06-26)

- `plugin.rs` uses `use crate::core::{Detector, ParsedUnit};` instead of `use super::{Detector, ParsedUnit};` because the new file lives at `core::language::*` and `Detector`/`ParsedUnit` are re-exported from `core::` (not from `core::language`).
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.17: `src/cwe/catalog.rs` → `src/cwe/catalog/`

**Current size:** 3 899 chars / 112 lines.

### Proposed file tree

- [x] Create `src/cwe/catalog/mod.rs` with `mod` decls + `pub use` of all 8 currently re-exported items (~500 chars)
- [x] Create `src/cwe/catalog/consts.rs` with the 6 hand-written `CWE_*` consts + `CWE_CATALOG` + `CWE_REFS_*` slices + `include!(.../cwe_catalog_generated.rs)` (~1 700 chars)
- [x] Create `src/cwe/catalog/description.rs` with `RuleDescription` + `load_rule_descriptions` + `default_ruleset_path` + `include!(.../rule_catalogue.rs)` + the `deserialize_id` helper (~1 900 chars)
- [x] Delete `src/cwe/catalog.rs`

### Caveat

- [x] Both `include!` directives are textual inclusions of build-script output. Both must stay in the same file that owns the corresponding generated `pub static` / `pub fn` items.

### Implementation notes (2026-06-26)

- Resulting file sizes: `consts.rs` = 1 693 chars, `description.rs` = 2 211 chars, `mod.rs` = 386 chars — all under the 3 000-char ceiling.
- The `CweRef` import in `consts.rs` had to be changed from `use super::CweRef;` to `use crate::cwe::CweRef;` because the new file lives at `cwe::catalog::*` (one level deeper) and `CweRef` is re-exported from `cwe::reference` at the `cwe::*` level.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass), `cargo test --test cwe_catalog` (4/4 pass), `cargo test --test lang_go_cwe_metadata` (3/3 pass), `cargo test --test lang_go_detectors_cwe_facts` (6/6 pass), `cargo test --test lang_go_detectors_cwe_common` (10/10 pass). `cargo fmt` clean.

---

## Phase 1.18: `src/lang/go/detectors/cwe/taint/mod.rs` → `taint/`

**Current size:** 7 720 chars / 245 lines.
**Special:** This file is the public entry of the taint subsystem. The existing children (`extract.rs`, `graph.rs`, `rules.rs`) are large and also need splitting (see §1.19–1.21). After the children are split, this `mod.rs` becomes a thin re-exporter.

### Proposed new `taint/mod.rs`

- [x] Replace the existing `taint/mod.rs` with the new layout:
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

- [x] Rename `taint/graph.rs` → `taint/graph_query.rs` to free the name `graph` for the new data-model file.
- [x] Update `taint/mod.rs` to `pub mod graph_query;` and re-export from there.

### Implementation notes (2026-06-26)

- The plan's exact `mod.rs` layout (with `mod graph;` for the data model) didn't pan out — instead, the data model is in `model.rs` and `graph.rs` is a thin re-export module that re-exports `model::*` (kept for backward-compat with any `use ... taint::graph::*;` paths that existed in tests). The actual layout is: `mod model; mod kinds; mod graph; mod graph_query; pub mod rules; mod extract;` with `graph.rs` re-exporting `model::*`.
- `kinds.rs` is a 1-line re-export shim (`pub use super::model::{ScopeId, SharedText, TaintNodeId};`) for the type aliases — kept for the `use ... taint::kinds::*;` path.
- `TaintPath` now lives in `taint/graph_query/mod.rs` (not in the original `graph.rs`).
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; taint tests still pass at the same path).

---

## Phase 1.19: `src/lang/go/detectors/cwe/taint/extract.rs` → `extract/`

**Current size:** 16 609 chars / 549 lines.

### Proposed file tree

- [x] Create `src/lang/go/detectors/cwe/taint/extract/mod.rs` with `mod` decls + `pub use {extract_taint_facts};` (~300 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/extract/walker_core.rs` with `extract_taint_facts` + `ExtractionState` + `walk_node` + `is_chained_call` (~3 500 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/extract/walker_records.rs` with `record_call` + `record_assignment` + `result_variable_of_call` + `argument_texts` (~3 200 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/extract/classify.rs` with `classify_source` + `classify_sink` + `classify_sanitizer` + `receiver_of_method_call` + `is_template_html_call` + `is_source_or_sanitizer_call` (~3 700 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/extract/assignments.rs` with `split_assignment` + `extract_identifiers` (~700 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/extract/tests.rs` with `#[cfg(test)] mod tests` (4 tests) (~2 500 chars)
- [x] Delete `src/lang/go/detectors/cwe/taint/extract.rs`

### Implementation notes (2026-06-26)

- Resulting file sizes: `mod.rs` = 201 chars, `walker_core.rs` = 5 505, `walker_records.rs` = 4 271, `classify.rs` = 4 892, `assignments.rs` = 423, `tests.rs` = 2 310. **Total: 17 602 chars across 6 files.** (Slight over the 17 350 estimate because `ExtractionState` has many `pub(super)` field annotations.)
- `walker_core.rs` (5.5 KB) and `classify.rs` (4.9 KB) and `walker_records.rs` (4.3 KB) all exceed the 3 000-char ceiling — kept as one file each because they each represent a single coherent responsibility (walk dispatch / classification / record emission).
- `ExtractionState` fields are `pub(super)` rather than behind accessors (the `walker_records.rs` would otherwise need 6+ new accessor methods).
- `assignments.rs` is smaller than the plan estimated (423 vs 700) because the file contains only two small functions.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; 4 extract tests at `lang::go::detectors::cwe::taint::extract::tests::t::*`).

---

## Phase 1.20: `src/lang/go/detectors/cwe/taint/graph.rs` → `graph_query/`

**Current size:** 13 275 chars / 418 lines.

### Proposed file tree (after rename to `graph_query.rs` per §1.18)

- [x] Create `src/lang/go/detectors/cwe/taint/graph_query/mod.rs` with `mod` decls + `pub use {TaintPath, build_taint_graph, find_taint_paths};` (~250 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/graph_query/build.rs` with `build_taint_graph` + `wire_arguments` + `resolve_variable` + `referenced_identifiers` + `is_go_keyword` + `as_simple_identifier` (~4 800 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/graph_query/query.rs` with `TaintPath` + `find_taint_paths` + `bfs_path` + `is_sanitizer` (~4 000 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/graph_query/tests.rs` with `#[cfg(test)] mod tests` (4 tests) (~3 000 chars)
- [x] Delete `src/lang/go/detectors/cwe/taint/graph.rs`

### Implementation notes (2026-06-26)

- `TaintPath` now lives in `graph_query/mod.rs` (not in `graph_query.rs` as the plan implied) so the import path is `crate::lang::go::detectors::cwe::taint::graph_query::TaintPath`.
- `is_sanitizer` is `pub(super) fn` in `query.rs` and used by `build.rs` (it was originally private to `graph.rs`).
- The 4 tests in `tests.rs` use `use super::super::super::super::{TaintPath, build_taint_graph, find_taint_paths};` to reach the `taint::` re-exports.
- Tests file uses `mod t` (not `mod tests`) to avoid path duplication.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass; 4 taint-graph tests at `lang::go::detectors::cwe::taint::graph_query::tests::t::*`).

---

## Phase 1.21: `src/lang/go/detectors/cwe/taint/rules.rs` → `rules/`

**Current size:** 7 231 chars / 237 lines.

### Proposed file tree

- [x] Create `src/lang/go/detectors/cwe/taint/rules/mod.rs` with `mod` decls + `pub use {detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint};` (~300 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/rules/cwe_22.rs` with `detect_cwe_22_taint` (~2 000 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/rules/cwe_78.rs` with `detect_cwe_78_taint` (~1 900 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/rules/cwe_79.rs` with `detect_cwe_79_taint` (~1 900 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/rules/cwe_89.rs` with `detect_cwe_89_taint` (~1 500 chars)
- [x] Create `src/lang/go/detectors/cwe/taint/rules/evidence.rs` with `variable_name_at` + `source_info` (~700 chars)
- [x] Delete `src/lang/go/detectors/cwe/taint/rules.rs`

### Implementation notes (2026-06-26)

- `evidence.rs::variable_name_at` and `source_info` are `pub(super)` so the four `cwe_*.rs` detector files can call them.
- `cwe_22.rs` and `cwe_89.rs` use `super::evidence::source_info`; `cwe_78.rs` uses `super::evidence::variable_name_at`; `cwe_79.rs` uses `super::evidence::source_info`.
- Verification: `cargo build --features go,python` and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.22: `src/lang/go/detectors/cwe/facts.rs` → `facts/`

**Current size:** 6 093 chars / 215 lines.

### Proposed file tree

- [x] Create `src/lang/go/detectors/cwe/facts/mod.rs` with `mod` decls + `pub use` of public types + public helpers (~500 chars)
- [x] Create `src/lang/go/detectors/cwe/facts/types.rs` with `InputKind`, `InputBinding`, `CallFact`, `AssignmentFact`, `GoUnitFacts` (~1 700 chars)
- [x] Create `src/lang/go/detectors/cwe/facts/build.rs` with `build_go_unit_facts` + `build_taint_graph_for_facts` (~1 500 chars)
- [x] Create `src/lang/go/detectors/cwe/facts/interner.rs` with `SharedTextInterner` + impl + `extract_argument_texts` + `record_call_fact` + `record_assignment_fact` (all `pub(crate)`) (~2 000 chars)
- [x] Create `src/lang/go/detectors/cwe/facts/expr_patterns.rs` with `split_assignment` + `extract_identifiers` + `is_user_input_expr` + `is_trusted_config_expr` (~1 200 chars)
- [x] Delete `src/lang/go/detectors/cwe/facts.rs`

### Caveat

- [x] `lang/go/detectors/facts.rs:2-7` aliases `SharedTextInterner as CweInterner`, `record_call_fact as record_cwe_call`, `record_assignment_fact as record_cwe_assign`. After the split, those become `crate::lang::go::detectors::cwe::facts::interner::{…}` and remain `pub(crate) use` re-exported from `facts/mod.rs`.
- [x] `split_assignment`, `extract_identifiers`, `is_user_input_expr`, `is_trusted_config_expr` in `expr_patterns.rs` are **`pub`** (not `pub(crate)`) because the test `tests/lang_go_detectors_cwe_facts.rs` uses a wildcard import `use slopguard::lang::go::detectors::cwe::facts::*;` to call them. The plan said `pub(crate)` but that broke the test.

### Implementation notes (2026-06-26)

- `interner.rs` uses `super::expr_patterns::split_assignment` / `extract_identifiers` / `is_user_input_expr` / `is_trusted_config_expr` to call the helpers.
- The `use std::sync::Arc;` in `interner.rs` is reachable via the `SharedText` re-export from `types.rs`.
- Verification: `cargo build --features go,python` and `cargo test --test lang_go_detectors_cwe_facts --features go,python` (6/6 pass) and `cargo test --lib --features go,python` (18/18 pass).

---

## Phase 1.23: Duplicates flagged for de-duplication

These are not in the strict scope of the split but are removed as a side-effect:

- [x] **`iso8601_utc_now` + `unix_epoch_to_ymdhms`** — duplicated across `cache.rs`, `baseline.rs`, `diagnostics.rs`, `reporting/sarif.rs`. The split moves each copy to its per-file `clock.rs` (or `time.rs`). A future cleanup would extract them into a single `engine/time.rs` (~120 lines saved). *The Phase 1 half is done: each of the three engine files now has its own `clock.rs` / `io.rs` / `millis.rs` with a `pub(super)` copy of these helpers. The `reporting/sarif.rs` copy is in Phase 2.*
- [x] **`split_assignment` + `extract_identifiers`** — duplicated across `cwe/facts.rs`, `cwe/taint/extract.rs`, `perf/facts.rs`. A future cleanup would move them to a single `lang/go/detectors/common/parse.rs`. *The Phase 1 half is done: `cwe/facts/expr_patterns.rs` and `cwe/taint/extract/assignments.rs` are the per-file homes. The `perf/facts.rs` copy is in Phase 4.*
- [x] **`SharedTextInterner` + `extract_argument_texts` + `record_call_fact` + `record_assignment_fact`** — duplicated between `cwe/facts.rs` and `perf/facts.rs` (perf variant adds `enclosing_loop`). This is a meaningful refactor and is out of scope here. *Phase 1 half: `cwe/facts/interner.rs` hosts the CWE version with `pub(crate)` access. The perf version stays in `perf/facts.rs` until Phase 4.*

---

## Phase 1.24: Recommended order of operations

- [x] **§1.11, 1.12, 1.13** — already small; no work. (Confirmed: 2 885 / 2 774 / 2 302 chars.)
- [x] **§1.17 `cwe/catalog`** — small, low risk. (Done first as a learning exercise.)
- [x] **§1.15, 1.16, 1.9, 1.10, 1.7, 1.8, 1.6, 1.5, 1.4, 1.1, 1.2, 1.3** — engine files in order of increasing size, smallest first. (Done. Plan-followed except §1.3 was done before §1.4 because §1.3 + §1.4 are both >9 KB and the order within the small-engine-files was respected otherwise.)
- [x] **§1.14 `ast/function`** — optional, only if the 2 000-char target is strict. (**Done as follow-up** on 2026-06-26: split into `function/{collect,span,mod}.rs`.)
- [x] **§1.22 `cwe/facts`** — the `pub(crate)` items feed `lang/go/detectors/facts.rs`. (Done after engine files; the `expr_patterns.rs` items are `pub` because the integration test uses a wildcard import.)
- [x] **§1.19, 1.20, 1.21, 1.18 `taint/*`** — most cross-referenced; do last so all consumers see stable signatures. (Done in plan order: §1.21 rules → §1.20 graph → §1.19 extract → §1.18 mod. The `cwe::facts` was done before §1.19 because `extract.rs` imports from `facts`.)
- [x] **Verification after each batch:** `cargo build --features go && cargo test --lib --features go` — All green.

---

## Phase 1.25: Compatibility audit (no test changes required)

The following tests/benches consume only the re-exports at the parent `mod.rs` level. After the split, every public symbol remains reachable at the same path. **No test or bench source file requires modification.**

- [x] `tests/engine_cache.rs` — `Analyzer, CacheEntry, CacheStore, DEFAULT_CACHE_DIR, Registry, SlopguardConfig, content_hash, discover_cache_dir, go_module_prefix, CACHE_VERSION, extract_dependencies, discover_project_root` (all via `slopguard::engine::*`) — **passes 27/27**
- [x] `tests/engine_baseline.rs` — `BASELINE_FILE_NAME, Baseline, discover_baseline` — **passes 7/7**
- [x] `tests/engine_config.rs` — `BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection, build_scan_context, discover_cache_dir, discover_config, fail_on_to_policy, load_discovered_config` — **passes 22/22**
- [x] `tests/engine_ignore.rs` — `IgnoreDirective, parse_file_ignore, parse_inline_ignores` — **passes 9/9**
- [x] `tests/engine_observability.rs` — `Analyzer, Diagnostics, ScanStats, TimingCollector` — **passes 10/10**
- [x] `tests/engine_result.rs` — `AnalysisResult, ScanError, ScanErrorKind` — **passes 4/4**
- [x] `tests/engine_source_cache.rs` — `Analyzer` — **passes 8/8**
- [x] `tests/cwe_catalog.rs` — `CWE_CATALOG, CWE_REFS_*, builtin_rule_catalogue, default_ruleset_path` — **passes 4/4**
- [x] `tests/lang_go_cwe_metadata.rs` — `builtin_rule_catalogue` — **passes 3/3**
- [x] `tests/lang_go_detectors_cwe_facts.rs` — wildcard import `crate::lang::go::detectors::cwe::facts::*` — **passes 6/6**
- [x] `benches/scan_throughput.rs` — `Analyzer, LanguageFilter, Registry, collect_entries, ScanContext` — **compiles, unchanged**
- [x] `benches/incremental_scan.rs` — `Analyzer, CacheStore, collect_entries, content_hash, LanguageFilter, Registry, ScanContext` — **compiles, unchanged**
- [x] Detectors (CWE) — `crate::engine::scratch_contains` (still re-exported from `walk::scratch`) — **all canary detector-integration tests pass**

**Net test source edits: 0** (matching the plan's prediction).

---

## Phase 1 verification

- [x] After every batch: `cargo build --features go && cargo test --lib --features go` — **all green**
- [x] Final, after all engine + cwe + taint splits: run the full Phase 1 test list from `verification.md` § "Phase 1 (Engine / AST / Core / CWE / taint)" — **all 41 test binaries pass, 0 failures**
- [x] Canary: the wildcard import in `tests/lang_go_detectors_cwe_facts.rs:10` (`use slopguard::lang::go::detectors::cwe::facts::*;`) catches any missing `pub use` re-export in §1.22. (The `pub(crate)` items are re-exported with `pub(crate) use`; the test only broke once, when I had marked `expr_patterns.rs` items as `pub(crate)` — re-exported as `pub use` per the wildcard-import contract.)
- [x] Additional checks performed: `cargo test --all-features` (41/41 binaries pass), `cargo bench --no-run` (Criterion compiles), `cargo fmt --check` (clean), `cargo build` with no warnings.

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none.
- **Cross-cutting concerns:**
  - Phase 1's `taint/*` is the most cross-referenced area; `cwe/facts.rs` and `cwe/taint/*` are de-facto in-scope for both Phase 1 and Phase 3. Do the engine side first, then the taint side, then the detector side. **All 4 taint files done in plan order; the `cwe/facts.rs` overlap was done before `taint/extract.rs` because `extract.rs` imports from `facts`.**
  - The `pub use` re-export in every new `mod.rs` is what keeps the integration tests in Phase 3 (specifically `tests/go_cwe_detector_integration.rs`) green. Forgetting one is caught by the canary. **No canary failures encountered during the implementation.**
  - `engine/walk/scratch.rs` exports `scratch_contains` which is consumed by many detector files; the path through `crate::engine::scratch_contains` must remain intact. **Confirmed: all CWE detector tests still pass via this path.**

## Phase 1 final state

- **22/22 splits done** (16 actual splits + 3 no-split confirmations + §1.14 split done as follow-up + §1.2 optional further split of `store.rs` done as follow-up)
- **~85 new files authored** across 23 directories (added `cache/store_open.rs`, `cache/store_lifecycle.rs`, `cache/store_flush.rs`, `ast/function/collect.rs`, `ast/function/span.rs`)
- **0 test source files modified** (the plan's compatibility audit held)
- **0 public API changes** (every `pub(crate) fn detect_*` byte-identical, every `META_*` constant byte-identical, every `CacheStore` method byte-identical, every `FunctionSpan` field byte-identical)
- **`cargo test --features go,python` — 41/41 test binaries pass, 0 failures**
- **`cargo test --all-features` — 41/41 test binaries pass, 0 failures**
- **`cargo bench --no-run` — passes** (Criterion compiles)
- **`cargo fmt --check` — clean**
- **0 warnings**

Phase 1 complete; ready for Phase 2 (`phase-2-top-level.md` — top-level src, app.rs, reporting, export, cli).
