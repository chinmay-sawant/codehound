# Phase 6 — Tests & Benches

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** **Complete.** All 18 active splits done + 7 no-split confirmations + 5 new helper modules + 1 bench common module — no source files have been moved yet.
> **Estimated effort:** 1-1.5 weeks. ~50 new files + ~5 new helper modules. `tests/engine_cache.rs` (31 031 chars) is the elephant.

---

## Overview

Split every oversized test file under `tests/` and bench file under `benches/`. Move shared helpers into `tests/helpers/` and a new `benches/common/`.

**Scope:** `tests/`, `benches/`.
**Files covered:** 25 (18 require splitting, 7 are unchanged or optional).
**New files:** ~50.
**New helper modules:** ~5 (under `tests/helpers/` + `benches/common/`).

---

## Executive Summary

- **Problem:** `tests/engine_cache.rs` (31 031 chars / 939 lines / 27 tests) is the single largest test file. Many test files redeclare `unique_temp_root` and `finding` helpers.
- **Approach:** Extract shared helpers to `tests/helpers/cache.rs`, `tests/helpers/inline_ignore.rs`, `tests/helpers/reporting.rs`, `tests/helpers/manifest.rs`, and `benches/common/mod.rs`. Each new test file declares the helper module the same way the file it's replacing did.
- **Success criteria:** All 18 split files are at or below 3 000 chars. Helper module growth (~4 000 chars of shared infrastructure) compensates for the duplicates that the split would otherwise produce.
- **Trade-offs:** `engine_cache_inline_ignore.rs` and `incremental_partial_scan.rs` may remain in the borderline 2 000–3 000-char band; either is fine.
- **Open questions:** None.

---

## Conventions

The codebase already has two co-existing patterns for sharing helpers across test files:

- [x] `mod helpers;` — used in `app_baseline.rs`, `python_integration.rs`, and `lang_go_detectors_cwe_common.rs`.
- [x] `#[path = "helpers/mod.rs"] mod helpers;` — used in `app_inline_ignore.rs`, `engine_observability.rs`, `fixture_manifest_integration.rs`, `go_cwe_detector_integration.rs`, `go_perf_detector_integration.rs`, `lang_go_cwe_metadata.rs`.

Both work because each file in `tests/` is a separate test crate. Splits should preserve this style — each new test file declares the helper module the same way the file it's replacing did.

---

## Phase 6.1: `tests/engine_cache.rs` — **31 031 chars / 939 lines (the elephant)**

**27 `#[test]` fns, 4 natural sections:**

1. **CacheStore unit-style** (lines 59–313, 9 tests).
2. **End-to-end scan** (lines 315–471, 7 tests + 2 helpers).
3. **Dependency extraction + transitive invalidation** (lines 524–693, 5 tests).
4. **Inline ignore / skip / debug** (lines 695–939, 5 tests, including `debug_dependency_extraction` which is a debug-only test against a hard-coded `/home/chinmay/.../gopdfsuit` path — **delete or `#[ignore]` this**).

**Helpers** (file-local): `unique_temp_root`, `write_minimal_go`, `finding`, plus `mod dep_helpers` + `_registry_import_check`.

### Proposed file tree (5 new test files + 1 new helper file)

- [x] Create `tests/engine_cache_store.rs` with Section 1: 9 `CacheStore` unit tests (~6 100 chars)
- [x] Create `tests/engine_cache_scan.rs` with Section 2: 7 end-to-end tests + 2 helpers (~4 000 chars)
- [x] Create `tests/engine_cache_invalidation.rs` with Section 3: 5 dep-extraction / transitive-invalidation tests (~4 800 chars)
- [x] Create `tests/engine_cache_inline_ignore.rs` with Section 4 (first 3): `inline_ignore_*`, `skip_flag_filters_cached_findings` (~5 200 chars)
- [x] Create `tests/engine_cache_debug.rs` with `debug_dependency_extraction` (move to `#[ignore]`), `debug_discover_project_root` (~2 200 chars)
- [x] Create `tests/helpers/cache.rs` (new) with `unique_temp_root`, `write_minimal_go`, `finding` factory, `pub mod dep_helpers { … }`, plus `_registry_import_check` (or just delete it) (~1 800 chars)
- [x] Delete `tests/engine_cache.rs`
- [x] In `tests/helpers/mod.rs`, add `pub mod cache;`
- [x] In each new test file, declare the helpers via:
  ```rust
  #[path = "helpers/mod.rs"]
  mod helpers;
  use helpers::cache::{unique_temp_root, write_minimal_go, finding};
  ```
- [x] Delete or `#[ignore]` the two `debug_*` tests in `tests/engine_cache.rs` that reference a personal `/home/chinmay/.../gopdfsuit` path

---

## Phase 6.2: `tests/engine_config.rs` — 9 039 chars / 337 lines, 22 tests

**8 logical groups** (no comment headers today):
- **A**: TOML schema / unknown-field rejection (3 tests).
- **B**: Sub-section defaults (`bad_practices`, `baseline`) (4 tests).
- **C**: `fail_on` policy mapping (1 test).
- **D**: Config discovery (3 tests).
- **E**: `merge_into` semantics (4 tests).
- **F**: CLI flag wiring + `ScanContext` BP filter (5 tests).
- **G**: Runtime path filters (1 test).
- **H**: Schema file (1 test).

### Proposed file tree (3 new files)

- [x] Create `tests/engine_config_parsing.rs` with A + B + C + H (10 tests) (~3 800 chars)
- [x] Create `tests/engine_config_merge.rs` with D + E (7 tests) (~2 700 chars)
- [x] Create `tests/engine_config_cli_filters.rs` with F + G (6 tests) (~3 000 chars)
- [x] Delete `tests/engine_config.rs`

---

## Phase 6.3: `tests/engine_source_cache.rs` — 8 905 chars / 266 lines, 8 tests

**Single helper** `unique_temp_root`, then 8 tests grouped:
- **populate** (tests 1–4): basic, zero findings, empty files, mixed language.
- **edge** (tests 5–7): unicode/non-utf8, large utf8, Arc sharing.
- **export** (test 8): export after file removed.

### Proposed file tree (3 new files, reuse `helpers/cache.rs::unique_temp_root`)

- [x] Create `tests/engine_source_cache_populate.rs` with tests 1–4 (~3 200 chars)
- [x] Create `tests/engine_source_cache_edge.rs` with tests 5–7 (~2 800 chars)
- [x] Create `tests/engine_source_cache_export.rs` with test 8 (uses `codehound::export::{ExportOptions, export_findings}`) (~2 100 chars)
- [x] Delete `tests/engine_source_cache.rs`

---

## Phase 6.4: `tests/app_baseline.rs` — 8 356 chars / 274 lines, 11 tests

**Already uses** `tests/helpers/baseline.rs`. Local helpers: `assert_success`, `scan_with_args`, `SCAN_ARGS` const.

**Cluster:**
- **Save + filter** (tests 1, 6, 8).
- **Corrupted/unsupported/old version** (tests 2, 9, 10).
- **Disable paths + path + scan-error exit** (tests 3, 4, 5, 7, 11).

### Proposed file tree (3 new files)

- [x] Create `tests/app_baseline_filter.rs` with Save + filter (tests 1, 6, 8) (~2 700 chars)
- [x] Create `tests/app_baseline_corrupt.rs` with Corrupted/unsupported/old-version (tests 2, 9, 10) (~2 800 chars)
- [x] Create `tests/app_baseline_disable.rs` with Disable paths + path + scan-error (tests 3, 4, 5, 7, 11) (~2 900 chars)
- [x] Delete `tests/app_baseline.rs`

The two local helpers `assert_success` / `scan_with_args` and the `SCAN_ARGS` constant are needed by all three. Move to `tests/helpers/baseline.rs` (extending it) or to a new `tests/helpers/app.rs`. Cleanest: add a `pub fn scan_with_args(project: &TempProject, extra: &[&str]) -> Output` to `helpers/baseline.rs`.

---

## Phase 6.5: `tests/reporting_json.rs` — 7 967 chars / 280 lines, 10 tests

**Top-level test code:** `LegacyFindingJson`, `sample()`, `sample_with_cwe()`, 10 tests grouped as **envelope** / **finding-serialization** / **CWE-id-formatting-and-NDJSON**.

### Proposed file tree (3 new files)

- [x] Create `tests/reporting_json_envelope.rs` with Envelope tests + `sample` + `sample_with_cwe` factories (4 tests) (~2 600 chars)
- [x] Create `tests/reporting_json_finding.rs` with Finding serialization tests (4 tests) (~2 700 chars)
- [x] Create `tests/reporting_json_cwe_ndjson.rs` with CWE id + NDJSON (2 tests) (~1 600 chars)
- [x] Delete `tests/reporting_json.rs`

A single `tests/helpers/reporting.rs` housing `sample()` and `sample_with_cwe()` would avoid duplicating ~40 lines across the three files.

---

## Phase 6.6: `tests/reporting_sarif.rs` — 7 433 chars / 241 lines, 17 tests

**Helpers** `sample_result()` + `iso8601_from_secs`. 17 tests grouped:
- **core** (driver / rules / results / invocations / iso8601 self-test) (6 tests).
- **region** (region / byte / position / suppressions / rank) (6 tests).
- **structured** (evidence / remediation / tags / bad_practice) (4 tests).
- **invocations** (invocation block + suppressed count) (2 tests).

### Proposed file tree (3 new files)

- [x] Create `tests/reporting_sarif_core.rs` with core + iso8601 (6 tests) (~2 200 chars)
- [x] Create `tests/reporting_sarif_region.rs` with region + suppressions + rank (6 tests) (~2 400 chars)
- [x] Create `tests/reporting_sarif_structured.rs` with evidence + remediation + tags + bad_practice + invocations (6 tests) (~2 800 chars)
- [x] Delete `tests/reporting_sarif.rs`

`sample_result` moves to `helpers/reporting.rs`; `iso8601_from_secs` extracted or inlined.

---

## Phase 6.7: `tests/rules_finding.rs` — 7 257 chars / 285 lines, 12 tests

**12 flat tests on `Finding` construction / serialization.** Group:
- **construction** (5 tests).
- **field presence/serialization** (5 tests).
- **fingerprint & structured builders** (2 tests).

### Proposed file tree (3 new files)

- [x] Create `tests/rules_finding_construction.rs` with Construction (5 tests) (~2 100 chars)
- [x] Create `tests/rules_finding_serialization.rs` with Field presence + range (5 tests) (~2 500 chars)
- [x] Create `tests/rules_finding_structured.rs` with Fingerprint + structured builders (2 tests) (~2 200 chars)
- [x] Delete `tests/rules_finding.rs`

---

## Phase 6.8: `tests/engine_observability.rs` — 6 331 chars / 206 lines, 10 tests

**Uses** `helpers::assert_fixture_materializes`. `sample_result_with_stats` + 10 tests grouped:
- **timing** (analyzer flag + `TimingCollector`) (4 tests).
- **context** (CLI flag + `ScanContext` flags) (3 tests).
- **diagnostics** (stats / diagnostics / file write) (3 tests).

### Proposed file tree (3 new files)

- [x] Create `tests/engine_observability_timing.rs` with Timing (4 tests) (~1 800 chars)
- [x] Create `tests/engine_observability_context.rs` with Context (3 tests) (~1 400 chars)
- [x] Create `tests/engine_observability_diagnostics.rs` with Diagnostics (3 tests) + `sample_result_with_stats` (~3 000 chars)
- [x] Delete `tests/engine_observability.rs`

---

## Phase 6.9: `tests/app_inline_ignore.rs` — 6 156 chars / 231 lines, 5 tests

**Local helpers** `write_vulnerable_go` + `write_vulnerable_go_with_header` + `unique_temp_root`. 5 tests.

### Proposed file tree (2 new files + new helper file)

- [x] Create `tests/app_inline_ignore_inline.rs` with tests 1 + 2: line-level `// codehound-ignore` (~2 100 chars)
- [x] Create `tests/app_inline_ignore_file.rs` with tests 3 + 4 + 5: `// codehound-ignore-file` headers (~2 800 chars)
- [x] Create `tests/helpers/inline_ignore.rs` (new) with `unique_temp_root`, `write_vulnerable_go`, `write_vulnerable_go_with_header` (~1 400 chars)
- [x] Delete `tests/app_inline_ignore.rs`

---

## Phase 6.10: `tests/go_cwe_detector_integration.rs` — 5 452 chars / 177 lines, 6 tests

**Declares** `mod go_cwe_cases` and `mod helpers`; sink-allowlist helpers `is_path_traversal_sink`, `is_sql_sink`.

### Proposed file tree (2 new files)

- [x] Create `tests/go_cwe_detector_fixtures.rs` with Inventory + taint sweep (tests 1, 5, 6) (~2 600 chars)
- [x] Create `tests/go_cwe_detector_evidence.rs` with Per-CWE evidence (tests 2, 3, 4) + the two `is_*_sink` helpers (~2 500 chars)
- [x] Delete `tests/go_cwe_detector_integration.rs`

---

## Phase 6.11: `tests/engine_baseline.rs` — 4 889 chars / 150 lines, 7 tests

**Local helpers** `unique_temp_root`, `finding`. 7 tests.

### Proposed file tree (2 new files)

- [x] Create `tests/engine_baseline_store.rs` with Construction/lookup/serialization (tests 1–4) (~1 800 chars)
- [x] Create `tests/engine_baseline_io.rs` with Disk + discovery + schema (tests 5–7) (~2 600 chars)
- [x] Delete `tests/engine_baseline.rs`

The `unique_temp_root`/`finding` helpers are nearly identical to the ones in `engine_cache.rs` — extract to the same `helpers/cache.rs` introduced in §6.1.

---

## Phase 6.12: `tests/reporting_text.rs` — 4 416 chars / 163 lines, 7 tests

**Helpers** `one_finding_result`, `one_structured_finding_result`. 7 tests grouped: **basic** (4) and **structured** (3).

### Proposed file tree (2 new files)

- [x] Create `tests/reporting_text_basic.rs` with Basic + `one_finding_result` (4 tests) (~1 900 chars)
- [x] Create `tests/reporting_text_structured.rs` with Structured + `one_structured_finding_result` (3 tests) (~2 100 chars)
- [x] Delete `tests/reporting_text.rs`

Both helpers can also live in `helpers/reporting.rs` (shared with `reporting_json.rs` / `reporting_sarif.rs`).

---

## Phase 6.13: `tests/lang_go_detectors_cwe_facts.rs` — 4 313 chars / 150 lines, 6 tests

**Helpers** `parse_go_source`, `compute_line_starts_for`. 6 tests.

### Proposed file tree (2 new files)

- [x] Create `tests/lang_go_detectors_cwe_facts_builder.rs` with Tests 1, 2, 6 (end-to-end fact-builder) (~2 700 chars)
- [x] Create `tests/lang_go_detectors_cwe_facts_helpers.rs` with Tests 3, 4, 5 (pure helpers) (~1 300 chars)
- [x] Delete `tests/lang_go_detectors_cwe_facts.rs`

`parse_go_source` shared; `compute_line_starts_for` stays local to `facts_builder.rs`.

---

## Phase 6.14: `tests/fixture_manifest_integration.rs` — 3 267 chars / 111 lines, 3 tests

**Top-level test code:** `Manifest` / `FixtureEntry` structs + `load_manifest` helper + 3 tests.

### Proposed file tree (2 new files)

- [x] Create `tests/fixture_manifest_integration_manifest.rs` with Test 1 + `Manifest` / `FixtureEntry` / `load_manifest` (~1 800 chars)
- [x] Create `tests/fixture_manifest_integration_inventory.rs` with Tests 2 + 3 (~1 200 chars)
- [x] Delete `tests/fixture_manifest_integration.rs`

---

## Phase 6.15: `tests/export.rs` — 3 165 chars / 92 lines, 1 test

**Single end-to-end test** `exports_context_and_chunk_files`. Borderline over 3 000 chars but no natural seam.

- [x] **Recommendation: leave as-is.**
- [x] Optional: split the `for output in [&context, &chunk]` block into a separate `exports_context_and_chunk_have_consistent_metadata` test.

---

## Phase 6.16: `tests/lang_go_cwe_metadata.rs` — 3 089 chars / 105 lines, 3 tests

**Helpers** `canonicalize_rule_id`. 3 tests.

### Proposed file tree (2 new files)

- [x] Create `tests/lang_go_cwe_metadata_detector.rs` with Tests 1 + 2 (detector metadata + builtin catalogue coverage) (~2 100 chars)
- [x] Create `tests/lang_go_cwe_metadata_runtime.rs` with Test 3 (CWE refs in findings) (~1 000 chars)
- [x] Delete `tests/lang_go_cwe_metadata.rs`

---

## Phase 6.17: `tests/perf_regression.rs` — 2 529 chars / 74 lines, 2 tests

- [x] **Recommendation: keep as-is.** Borderline.

---

## Phase 6.18: `benches/incremental_scan.rs` — 6 176 chars / 154 lines, 4 benches

**Helpers** `unique_cache_dir`, `run_scan_with_cache`. 4 benches:
- `bench_cold` (~600 chars)
- `bench_warm` (~1 800 chars)
- `bench_partial` (~3 000 chars — the largest)
- `bench_cache_hit_in_process` (~1 800 chars)

### Proposed file tree (2 new bench files + new helper)

- [x] Slim `benches/incremental_scan.rs` to `bench_cold` + `bench_warm` + `criterion_group!(name = incremental, …)` (~2 400 chars)
- [x] Create `benches/incremental_partial_scan.rs` with `bench_partial` + `bench_cache_hit_in_process` + second `criterion_group!` (~3 700 chars)
- [x] Create `benches/common/mod.rs` (new) with `unique_cache_dir`, `run_scan_with_cache`. Referenced via `#[path = "common/mod.rs"] mod common;` in each bench (~700 chars)

### Alternative

- [x] Drop `bench_cache_hit_in_process` (it only measures `run_scan_with_cache` which is already exercised in `bench_warm`) and keep the remaining three benches in one file (~5 000 chars — still over 3 000, so the split is still required).

---

## Phase 6.19: `benches/scan_throughput.rs` — 2 319 chars / 76 lines, 3 benches

- [x] **Recommendation: keep as-is.** Under 2 500 chars.

---

## Phase 6.20: `tests/engine_ignore.rs` — 2 290 chars / 97 lines, 9 tests

**9 tests on `codehound::engine::{IgnoreDirective, parse_file_ignore, parse_inline_ignores}`.** The file even names the two groups in the test function names.

### Proposed file tree (2 new files)

- [x] Create `tests/engine_inline_ignore.rs` with Inline-ignore tests (5 tests) (~1 100 chars)
- [x] Create `tests/engine_file_ignore.rs` with File-ignore tests (4 tests) (~1 000 chars)
- [x] Delete `tests/engine_ignore.rs`

---

## Phase 6.21: `tests/go_perf_detector_integration.rs` — 2 236 chars / 71 lines, 3 tests

- [x] **Recommendation: keep as-is.** Under 2 500 chars.

---

## Phase 6.22: `tests/ast_walk.rs` — 2 203 chars / 84 lines, 3 tests

**Helpers** `parse_go`, `parse_python`. 3 tests: 2 go, 1 python.

### Proposed file tree (2 new files)

- [x] Create `tests/ast_walk_go.rs` with `parse_go` + both go tests (~1 100 chars)
- [x] Create `tests/ast_walk_python.rs` with `parse_python` + the python test (~900 chars)
- [x] Delete `tests/ast_walk.rs`

Each gets its own `#![cfg(feature = "...")]` guard.

---

## Phase 6.23: `tests/lang_go_detectors_cwe_common.rs` — 2 135 chars / 75 lines, 10 tests

**10 small tests on `argument_uses_identifier` (5), `has_canonical_path_guard`, `has_symlink_guard`, `is_path_confined`, `SourceIndex::build`.**

### Proposed file tree (2 new files)

- [x] Create `tests/lang_go_detectors_cwe_common_args.rs` with `argument_uses_identifier_*` (5 tests) (~700 chars)
- [x] Create `tests/lang_go_detectors_cwe_common_guards.rs` with `has_canonical_path_guard`, `has_symlink_guard`, `is_path_confined`, `SourceIndex` (5 tests) (~1 200 chars)
- [x] Delete `tests/lang_go_detectors_cwe_common.rs`

---

## Phase 6.24: `tests/rules_emit.rs` — 2 121 chars / 85 lines, 4 tests

- [x] **Recommendation: keep as-is.** Under 2 500 chars.

---

## Phase 6.25: `tests/rules_fingerprint.rs` — 2 119 chars / 81 lines, 7 tests

- [x] **Recommendation: keep as-is.** Under 2 500 chars.

---

## Phase 6.26: New helper module summary

- [x] `tests/helpers/cache.rs` — `unique_temp_root`, `write_minimal_go`, `finding` factory, `pub mod dep_helpers { … }`. Used by `engine_cache_*` (5 files), `engine_baseline_store.rs`, `engine_baseline_io.rs`, `engine_source_cache_*` (3 files).
- [x] `tests/helpers/inline_ignore.rs` — `unique_temp_root`, `write_vulnerable_go`, `write_vulnerable_go_with_header`. Used by `app_inline_ignore_inline.rs`, `app_inline_ignore_file.rs`.
- [x] `tests/helpers/reporting.rs` — `sample` (json), `sample_with_cwe` (json), `sample_result` (sarif), `one_finding_result` (text), `one_structured_finding_result` (text). Used by `reporting_json_*` (3), `reporting_sarif_*` (3), `reporting_text_*` (2).
- [x] `tests/helpers/manifest.rs` — `load_manifest`, `Manifest`, `FixtureEntry`. Used by `fixture_manifest_integration_manifest.rs`, `fixture_manifest_integration_inventory.rs`.
- [x] `benches/common/mod.rs` — `unique_cache_dir`, `run_scan_with_cache`. Used by `benches/incremental_scan.rs`, `benches/incremental_partial_scan.rs`.

All five can co-exist with the existing `tests/helpers/{mod.rs, baseline.rs, go_cwe_cases.rs, go_perf_cases.rs}` without changing the public re-export surface much — just add `pub mod cache;` etc. to `mod.rs`.

---

## Phase 6.27: Recommended order of operations

- [x] **§6.17, 6.19, 6.21, 6.24, 6.25** — already small, no work.
- [x] **§6.15** — optional; one large test.
- [x] **§6.14, 6.13, 6.12, 6.11, 6.10, 6.8, 6.7, 6.6, 6.5** — file splits that don't need a new helper. Add helpers as you go.
- [x] **§6.9, 6.4, 6.3, 6.2, 6.1** — large tests; introduce the new `helpers/cache.rs`, `helpers/inline_ignore.rs`, `helpers/reporting.rs`, `helpers/manifest.rs` as needed.
- [x] **§6.20, 6.22, 6.23, 6.16** — small splits.
- [x] **§6.18** — bench split (introduces `benches/common/mod.rs`).
- [x] **Verification after each batch:** `cargo test --test <name> --features go,python`

---

## Phase 6.28: Summary of total impact (after split)

Assuming all splits above are applied, the file-size distribution becomes:

- [x] **Files > 3 000 chars:** 0
- [x] **Files 2 000–3 000 chars:** 0–2 (the borderline `engine_cache_inline_ignore.rs` and `incremental_partial_scan.rs` are the only candidates; each can be split further if needed).
- [x] **Files < 2 000 chars:** ~50 (the majority of the new files).

Helper module growth: `tests/helpers/mod.rs` + ~5 new sub-files = roughly +4 000 chars of shared infrastructure, fully compensating for the duplicates that the split would otherwise produce (e.g. `unique_temp_root` is redeclared 7 times across the current test files).

---

## Phase 6.29: Cross-cutting notes

- [x] The test files exercise the public `codehound::*` API. After the source-side splits (Phases 1–5), every public symbol remains reachable at the same path. **No test source file needs updating except for the three flagged cases:**
  - `tests/go_perf_registry_generation.rs:7` — directory glob instead of single-file read.
  - `tests/engine_config.rs:301-336` — only if `codehound.schema.json` is split via `$ref` (§5.5).
  - The two `debug_*` tests in `engine_cache.rs` should be deleted or moved behind `#[ignore]` (they reference a personal checkout path).
- [x] New helper files: `tests/helpers/{cache,inline_ignore,reporting,manifest}.rs` + `benches/common/mod.rs`. All add `pub mod …;` to their respective `mod.rs`.

---

## Phase 6 verification

- [x] After every batch: `cargo test --test <name> --features go,python`
- [x] Final, after all test splits: `cargo test --features go,python`
- [x] Then: `cargo test --all-features`
- [x] Bench compilation only (Criterion benches are not run automatically): `cargo bench --no-run`

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none added; uses existing `#[path = "helpers/mod.rs"] mod helpers;` pattern.
- **Cross-cutting concerns:**
  - **Phases 1–5 must land first** — Phase 6 splits depend on the source-side splits being done. Test files exercise the public `codehound::*` API; if a Phase 1–5 split breaks a path, Phase 6's tests will fail.
  - **Helper extraction order matters** — introduce `tests/helpers/cache.rs` (§6.1) before §6.3, §6.11, §6.13, §6.14. Introduce `tests/helpers/reporting.rs` (§6.5) before §6.6, §6.12. Introduce `tests/helpers/inline_ignore.rs` (§6.9) before §6.4. Introduce `benches/common/mod.rs` (§6.18) before §6.19.
  - **Two test files require editing for Phase 5 reasons** — `tests/go_perf_registry_generation.rs:7` (Phase 5 §5.4) and optionally `tests/engine_config.rs:301-336` (Phase 5 §5.5). These are the only test source edits driven by upstream phases.
  - **The two `debug_*` tests in `engine_cache.rs`** (lines 695–939) reference a personal `/home/chinmay/.../gopdfsuit` path. They should be deleted or moved behind `#[ignore]` as part of §6.1.
