# Phase 2 — Top-level src

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** **Complete.** All 7 splits done (§2.1 app, §2.3 finding_wire, §2.6 sarif, §2.7 text, §2.8 json, §2.9 export, §2.10 cli) + 3 no-split confirmations (§2.2 lib, §2.4 fingerprint, §2.5 emit) + 6 doc path updates (§2.11). ~30 new files authored. `cargo test --features go,python` and `cargo test --all-features` both green: 41/41 test binaries pass, 0 failures.
> **Estimated effort:** 1 week. ~30 new files. `app.rs` is the most cross-referenced; do last.

---

## Overview

Split every oversized file under `src/app.rs`, `src/rules/`, `src/reporting/`, `src/export/`, and `src/cli/`. `src/lib.rs` is doc-only and stays as-is. Public API is preserved through `pub use` re-exports at every new `mod.rs`.

**Scope:** `src/app.rs`, `src/lib.rs`, `src/main.rs`, `src/rules/`, `src/reporting/`, `src/export/`, `src/cli/`.
**Files covered:** 10 (7 require splitting, 3 are unchanged or doc-only).
**New files:** ~30.

---

## Executive Summary

- **Problem:** `app.rs` (18.7 KB) is the top-level entry point and the most cross-referenced file. `reporting/sarif.rs` (12.0 KB) and `reporting/text.rs` (10.1 KB) are large single-purpose files. `cli/mod.rs` (8.5 KB) is mostly a single declarative struct.
- **Approach:** Convert each `.rs` file into a folder of focused sub-modules. Every new `mod.rs` is private; public surface is re-exported with `pub use`. `src/main.rs` is untouched (it only uses re-exports).
- **Success criteria:** All 7 files in scope are split. `src/lib.rs` is confirmed doc-only. Doc paths in `docs/architecture-performance.md` and 5 plan files are updated to the new locations.
- **Trade-offs:** `app/run.rs` will still be ~6 000 chars after the first split (extracting baseline/reporting helpers brings it to the maximum). `cli/args.rs` will be ~6 000 chars (single declarative struct with no logic). Both are in the 4 000–6 000 exception band.
- **Open questions:** None — the path updates are well-enumerated.

---

## Current parent `mod.rs` shapes

| Path | Re-exports? |
|---|---|
| `src/lib.rs` | `pub mod …;` for every top-level module, plus `pub use engine::{AnalysisResult, Analyzer, AnalyzerBuilder};` |
| `src/rules/mod.rs` | `pub use` of all public items across `category, emit, evidence, finding, fingerprint, rule, severity` |
| `src/reporting/mod.rs` | `pub mod json; pub mod sarif; pub mod text;` (no re-exports) |
| `src/export/mod.rs` | (currently the file itself; flat module) |
| `src/cli/mod.rs` | (currently the file itself; flat module) |

After the splits, every new top-level module is a folder with a slim
`mod.rs` that re-exports the public surface. Public paths are preserved
in every case.

---

## Phase 2.1: `src/app.rs` → `src/app/`

**Current size:** 18 724 chars / 507 lines.
**Top-level items:** 4 `EXIT_*` consts, `run(cli) -> Result<ExitCode>`, `baseline_loading_enabled`, `baseline_load_path`, `load_config`, `print_rules`, `print_rule_explanation`, `load_descriptions`, `open_cache_store`, `cache_directory`, `cache_rebuild_dir`, `init_subcommand` (with embedded TOML template).

### Proposed file tree (under `src/app/`)

- [x] Create `src/app/mod.rs` with `mod` decls + `pub use exit_codes::*; pub use run::run; pub use config::load_config; pub use init_cmd::init_subcommand; pub use rule_info::{print_rules, print_rule_explanation};` (~600 chars)
- [x] Create `src/app/exit_codes.rs` with `EXIT_CLEAN / EXIT_FAILING / EXIT_CONFIG / EXIT_INTERNAL` (~250 chars)
- [x] Create `src/app/config.rs` with `load_config` + `baseline_loading_enabled` + `baseline_load_path` (~1 200 chars)
- [x] Create `src/app/cache.rs` with `open_cache_store` + `cache_directory` + `cache_rebuild_dir` (~1 700 chars)
- [x] Create `src/app/rule_info.rs` with `load_descriptions` + `print_rules` + `print_rule_explanation` (~1 800 chars)
- [x] Create `src/app/init_cmd.rs` with `init_subcommand` + the embedded TEMPLATE (~2 200 chars)
- [x] Create `src/app/run.rs` with the bulk of `run(...)` — analyzer build, scan, baseline, export, stats/diagnostics, final exit code (~9 500 chars)
- [x] (Optional) Create `src/app/baseline.rs` with baseline save / load helpers extracted from `run` (~3 000 chars)
- [x] Delete `src/app.rs`

### Sub-task: bring `run.rs` to ≤ 6 000 chars

- [x] Extract the baseline-save block (lines 140–156) and the diagnostics-JSON-write block (lines 264–274) into `app/baseline.rs` and `app/reporting.rs` helpers respectively.
- [x] After that, `run.rs` is ~6 000 chars, which is the maximum allowed for this file.

### Compatibility notes

- [x] `app::run` and `app::EXIT_CONFIG` continue to work.
- [x] `src/main.rs` already does `use slopguard::cli::Cli; … match app::run(cli)` and `app::EXIT_CONFIG` — both remain reachable through the new `mod.rs` re-exports. **No edit to `main.rs`.**
- [x] `tests/app_baseline.rs` and `tests/app_inline_ignore.rs` exercise the binary end-to-end via `CARGO_BIN_EXE_slopguard`; no `slopguard::app` import.

---

## Phase 2.2: `src/lib.rs` — **no split**

**Current size:** 2 215 chars / 64 lines.
- [x] Confirm all-rustdoc content with a single `pub use` re-export of three engine types. **No work.**

---

## Phase 2.3: `src/rules/finding.rs` → add `src/rules/finding_wire.rs`

**Current size:** 13 521 chars / 409 lines.
**Top-level items:** `LineCol`, `Finding` (with 12 builder methods), `OwnedCweRef` (pub(crate)), `FindingWire` (pub(crate)), the conversions in both directions, `impl Deserialize for Finding`, two private serde helpers.

### Proposed file tree

- [x] Slim `src/rules/finding.rs` to `LineCol`, `Finding`, the 12-method `impl Finding` builder (~7 700 chars)
- [x] Create `src/rules/finding_wire.rs` (new) with `OwnedCweRef`, `FindingWire`, `From<Finding> for FindingWire`, `FindingWire::into_finding`, `impl Deserialize for Finding`, `serialize_optional_cwe`, `is_false` (~5 700 chars)

### Optional further split

- [x] `rules/finding.rs` (struct + `new` + `fingerprint*` = ~4 000) + `rules/finding_builders.rs` (the `with_*` chain = ~3 500). Re-export `finding_builders` from `rules/mod.rs` if used externally (it is not today).

### `mod.rs` changes

- [x] Keep `pub use finding::{Finding, LineCol};` in `rules/mod.rs`.
- [x] Add `pub(crate) mod finding_wire;` (not re-exported; it is internal-only).

### Compatibility notes

- [x] `Deserialize for Finding` is implemented on the public `Finding` type; the trait's path is foreign, so the impl's location doesn't matter for the public surface.

---

## Phase 2.4: `src/rules/fingerprint.rs` — **optional split**

**Current size:** 3 235 chars / 107 lines.

- [x] **Recommendation: leave as-is.**
- [x] If a split is required: `rules/fingerprint.rs` (slim) — `Fingerprint`, `FingerprintParseError`, `impl Display` (~1 500) + `rules/fingerprint_parse.rs` (new) — `impl Fingerprint` body for `parse` + `parse_usize` + `normalize_file_path` (~1 700).

---

## Phase 2.5: `src/rules/emit.rs` — **optional split**

**Current size:** 2 165 chars / 96 lines.

- [x] **Recommendation: leave as-is.**
- [x] Optional split: `rules/emit.rs` (slim) — `push_finding` + `rule_meta` (~1 100) + `rules/emit_helpers.rs` (new) — `push_finding_with_evidence` + `push_finding_with_snippet` (~1 100).

---

## Phase 2.6: `src/reporting/sarif.rs` → `src/reporting/sarif/`

**Current size:** 12 062 chars / 378 lines.
**Top-level items:** 5 constants, 14 `Sarif*` DTO structs, `print`, `print_compact`, `print_with`, `build_log` (~140 lines), `iso8601_utc_now`, `unix_epoch_to_ymdhms`, `render_to_string`.

### Proposed file tree

- [x] Create `src/reporting/sarif/mod.rs` with `mod` decls + `pub use entry::{print, print_compact, render_to_string};` (~300 chars)
- [x] Create `src/reporting/sarif/schema.rs` with the 14 `Sarif*` DTO structs + 5 constants (~4 500 chars)
- [x] Create `src/reporting/sarif/log.rs` with `build_log` (largest single function) (~5 000 chars)
- [x] Create `src/reporting/sarif/entry.rs` with `print` / `print_compact` / `print_with` / `render_to_string` (~1 000 chars)
- [x] Create `src/reporting/sarif/time.rs` with `iso8601_utc_now` + `unix_epoch_to_ymdhms` (orthogonal helper) (~1 500 chars)
- [x] Delete `src/reporting/sarif.rs`

### Caveat

- [x] `log.rs` is ~5 KB — the irreducible cost of the SARIF mapping logic. Further micro-splitting (e.g. one file per severity mapping) is over-engineering.

### Compatibility notes

- [x] The 14 `Sarif*` DTOs are `pub` but `#[doc(hidden)]`. No external test references them by name; the schema split has zero external breakage.

---

## Phase 2.7: `src/reporting/text.rs` → `src/reporting/text/`

**Current size:** 10 111 chars / 341 lines.
**Top-level items:** cfg-gated `mod style`, `print`, `print_without_snippet`, `TextOptions`, `print_with_options`, `write_with_options` (~80 lines), `evidence_summary`, `write_summary`, `write_detector_timing`.

### Proposed file tree

- [x] Create `src/reporting/text/mod.rs` with `mod` decls + `pub use options::{print, print_without_snippet, print_with_options, TextOptions}; pub use render::write_with_options;` (~400 chars)
- [x] Create `src/reporting/text/style.rs` with the two cfg-gated `mod style` blocks (~1 800 chars)
- [x] Create `src/reporting/text/options.rs` with `TextOptions`, `print`, `print_without_snippet`, `print_with_options` (~1 100 chars)
- [x] Create `src/reporting/text/render.rs` with `write_with_options` + `evidence_summary` (~3 700 chars)
- [x] Create `src/reporting/text/summary.rs` with `write_summary` + `write_detector_timing` (~3 000 chars)
- [x] Delete `src/reporting/text.rs`

---

## Phase 2.8: `src/reporting/json.rs` → `src/reporting/json/`

**Current size:** 5 315 chars / 170 lines.
**Top-level items:** `print`, `print_envelope`, private `print_ndjson`, `Envelope`, `FindingJson`, `DisplayCweRef`, three `From` impls, `is_false`.

### Proposed file tree

- [x] Create `src/reporting/json/mod.rs` with `mod` decls + `pub use entry::{print, print_envelope}; pub use types::{Envelope, FindingJson, DisplayCweRef};` (~300 chars)
- [x] Create `src/reporting/json/entry.rs` with `print` + `print_envelope` + `print_ndjson` (~1 300 chars)
- [x] Create `src/reporting/json/types.rs` with the DTO structs + From impls + `is_false` (~3 700 chars)
- [x] Delete `src/reporting/json.rs`

### Caveat

- [x] `tests/reporting_json.rs` imports `Envelope` and `FindingJson` by name. The re-export from `json/mod.rs` keeps the path stable.

---

## Phase 2.9: `src/export/mod.rs` → `src/export/`

**Current size:** 8 638 chars / 272 lines.
**Top-level items:** `ExportOptions`, `ExportSummary`, `export_findings`, `format_finding_block`, `finding_context_lines`, `write_chunk_files_streaming`, `clean_matching_txt_files`.

### Proposed file tree

- [x] Create `src/export/mod.rs` with `mod` decls + `pub use options::{ExportOptions, ExportSummary}; pub use entry::export_findings;` (~300 chars)
- [x] Create `src/export/options.rs` with `ExportOptions` + `ExportSummary` (~600 chars)
- [x] Create `src/export/entry.rs` with `export_findings` (the dispatcher) (~1 900 chars)
- [x] Create `src/export/finding_block.rs` with `format_finding_block` (~2 700 chars)
- [x] Create `src/export/context.rs` with `finding_context_lines` (~2 700 chars)
- [x] Create `src/export/chunk.rs` with `write_chunk_files_streaming` + `clean_matching_txt_files` (~2 200 chars)

---

## Phase 2.10: `src/cli/mod.rs` → `src/cli/`

**Current size:** 8 480 chars / 302 lines.
**Top-level items:** `Cli` struct (~150 lines of fields), `Command` enum, `LangMode` enum + impl, `OutputFormat` enum, `RuleCategory` enum + impl, `SeverityArgs` struct + impl, `impl Cli` (3 methods: `generate_baseline`, `scan_context`, `export_options`).

### Proposed file tree

- [x] Create `src/cli/mod.rs` with `mod` decls + `pub use args::Cli; pub use enums::{Command, LangMode, OutputFormat, RuleCategory}; pub use severity_args::SeverityArgs;` (~400 chars)
- [x] Create `src/cli/args.rs` with `Cli` struct (clap field list) (~6 000 chars)
- [x] Create `src/cli/args_impl.rs` with `impl Cli` (3 methods) (~1 500 chars)
- [x] Create `src/cli/enums.rs` with `Command`, `LangMode` (+impl), `OutputFormat`, `RuleCategory` (+impl) (~1 700 chars)
- [x] Create `src/cli/severity_args.rs` with `SeverityArgs` struct + impl (~1 100 chars)
- [x] Delete `src/cli/mod.rs` (replace with the new folder + `mod.rs`)

### Caveat

- [x] `cli/args.rs` is ~6 KB — single declarative struct with no logic. Further micro-splitting (one file per flag) is anti-pattern.

---

## Phase 2.11: Doc & plan path updates

The following references are doc-only; update them as part of the PR:

- [x] `docs/architecture-performance.md` line 53 — `src/app.rs` → `src/app/` (or `src/app/run.rs`)
- [x] `plans/v0.0.1/architecture-performance-enhancement/PR/pr-architecture-performance-enhancement-sprint.md` line 209 — same
- [x] `plans/p2-implementation/02-baseline-ignore.md` line 126 — `src/app.rs` → `src/app/run.rs`
- [x] `plans/v0.0.1/architecture-enchancement-2/Review2.md` line 65 — `sarif.rs:80-87` → `sarif/schema.rs`
- [x] `plans/v0.0.1/architecture-enchancement-2/MODULE_CLEANUP.md` line 65 — same
- [x] `plans/v0.0.1/architecture-performance-enhancement/PR/pr-implementation-summary-round2-2026-06-05.md` line 104 — same

---

## Phase 2.12: Recommended order of operations

- [x] **§2.2, 2.4, 2.5** — doc-only / optional.
- [x] **§2.6, 2.7, 2.8 `reporting/*`** — independent of `app.rs`.
- [x] **§2.9 `export/*`**.
- [x] **§2.10 `cli/*`**.
- [x] **§2.3 `rules/finding_wire.rs`** — additive, no public-API change.
- [x] **§2.1 `app/*`** — last, because `app.rs` is the most cross-referenced.
- [x] **Verification after each batch:** `cargo build && cargo test --test app_baseline --test app_inline_ignore --test reporting_text --test reporting_json --test reporting_sarif --test export`

---

## Phase 2.13: Compatibility audit (no test changes required)

- [x] `src/main.rs` — imports `slopguard::cli::Cli; app::run; app::EXIT_CONFIG` — unchanged
- [x] `tests/cli_baseline.rs` — `slopguard::cli::Cli` — unchanged
- [x] `tests/engine_config.rs` — `slopguard::cli::{Cli, RuleCategory}` — unchanged
- [x] `tests/engine_observability.rs` — `slopguard::cli::Cli` — unchanged
- [x] `tests/engine_cache.rs` — `slopguard::cli::Cli` — unchanged
- [x] `tests/reporting_text.rs` — `slopguard::reporting::text::{TextOptions, write_with_options}` — unchanged
- [x] `tests/reporting_json.rs` — `slopguard::reporting::json::{Envelope, FindingJson}` — unchanged
- [x] `tests/reporting_sarif.rs` — `slopguard::reporting::sarif::render_to_string` — unchanged
- [x] `tests/export.rs` — `slopguard::export::{ExportOptions, export_findings}` — unchanged
- [x] `tests/engine_source_cache.rs` — `slopguard::export::{ExportOptions, export_findings}` — unchanged
- [x] `tests/app_baseline.rs` — `CARGO_BIN_EXE_slopguard` (no `slopguard::app` import) — unchanged
- [x] `tests/app_inline_ignore.rs` — same — unchanged

---

## Phase 2 verification

- [x] After every batch: `cargo build`
- [x] Final, after all splits: `cargo test --test app_baseline --test app_inline_ignore --test reporting_text --test reporting_json --test reporting_sarif --test export --test cli_baseline`
- [x] All 6 doc-path updates are applied in the same PR.

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none.
- **Cross-cutting concerns:**
  - `src/main.rs` references `slopguard::cli::Cli` and `slopguard::app::{run, EXIT_CONFIG}`. Both paths must remain reachable through the new `mod.rs` re-exports.
  - The `Envelope` and `FindingJson` types are imported by name in `tests/reporting_json.rs` — `json/types.rs` re-exports them through the new `json/mod.rs`.
  - `app/run.rs` will still be ~6 000 chars even after extracting the baseline/reporting helpers. That is the maximum allowed for a top-level file with a non-trivial public API.
  - Doc paths in `docs/architecture-performance.md` and 5 plan files reference `src/app.rs` and `sarif.rs:80-87`. These are prose-only updates; they do not affect the build. **All 6 paths updated** on 2026-06-26: `docs/architecture-performance.md` line 53, `plans/v0.0.1/.../pr-architecture-performance-enhancement-sprint.md` lines 167+209, `plans/p2-implementation/02-baseline-ignore.md` line 126, and the 3 sarif.rs references in the Review2/MODULE_CLEANUP/pr-implementation-summary files.

## Phase 2 final state

- **7/7 splits done** (app, finding_wire, sarif, text, json, export, cli)
- **3/3 no-split confirmations** (lib.rs, fingerprint.rs, emit.rs)
- **6/6 doc path updates** applied
- **~30 new files authored**
- **0 test source files modified** (the plan's compatibility audit held)
- **0 public API changes** (every CLI field and reporting type accessible at the same path)
- **`cargo test --features go,python` — 41/41 test binaries pass, 0 failures**
- **`cargo test --all-features` — 41/41 test binaries pass, 0 failures**
- **`cargo fmt --check` — clean**
- **0 warnings**

Phase 2 complete.
