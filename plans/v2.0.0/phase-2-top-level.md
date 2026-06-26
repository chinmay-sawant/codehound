# Phase 2 — Top-level src

**Scope:** `src/app.rs`, `src/lib.rs`, `src/main.rs`, `src/rules/`,
`src/reporting/`, `src/export/`, `src/cli/`.

**Files covered:** 10 (7 require splitting, 3 are unchanged or doc-only).

**New files:** ~30.

## 2.0 Current parent `mod.rs` shapes

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

## 2.1 `src/app.rs` → `src/app/`

**Current size:** 18 724 chars / 507 lines.

**Top-level items:** 4 `EXIT_*` consts, `run(cli) -> Result<ExitCode>`,
`baseline_loading_enabled`, `baseline_load_path`, `load_config`,
`print_rules`, `print_rule_explanation`, `load_descriptions`,
`open_cache_store`, `cache_directory`, `cache_rebuild_dir`,
`init_subcommand` (with embedded TOML template).

**Proposed split** (under `src/app/`):

| New file | Contents | Approx chars |
|---|---|---:|
| `app/mod.rs` | `mod` decls + `pub use exit_codes::*; pub use run::run; pub use config::load_config; pub use init_cmd::init_subcommand; pub use rule_info::{print_rules, print_rule_explanation};` | ~600 |
| `app/exit_codes.rs` | `EXIT_CLEAN / EXIT_FAILING / EXIT_CONFIG / EXIT_INTERNAL`. | ~250 |
| `app/config.rs` | `load_config` + `baseline_loading_enabled` + `baseline_load_path`. | ~1 200 |
| `app/cache.rs` | `open_cache_store` + `cache_directory` + `cache_rebuild_dir`. | ~1 700 |
| `app/rule_info.rs` | `load_descriptions` + `print_rules` + `print_rule_explanation`. | ~1 800 |
| `app/init_cmd.rs` | `init_subcommand` + the embedded TEMPLATE. | ~2 200 |
| `app/run.rs` | the bulk of `run(...)` — analyzer build, scan, baseline, export, stats/diagnostics, final exit code. | ~9 500 |
| `app/baseline.rs` *(optional)* | baseline save / load helpers extracted from `run`. | ~3 000 |

**`run.rs` may still be ~9 500 chars** — the irreducible core. To bring
it under 5–6 KB, extract the baseline-save block (lines 140–156) and
the diagnostics-JSON-write block (lines 264–274) into `app/baseline.rs`
and `app/reporting.rs` helpers respectively. After that, `run.rs` is
~6 000 chars, which is the maximum allowed for this file.

**Conversion steps:**
- Move `src/app.rs` content into `src/app/{exit_codes,config,cache,rule_info,init_cmd,run,baseline}.rs` plus the new `src/app/mod.rs`.
- Delete `src/app.rs`.
- `src/main.rs` already does `use slopguard::cli::Cli; … match app::run(cli)` and `app::EXIT_CONFIG` — both remain reachable through the new `mod.rs` re-exports. **No edit to `main.rs`.**

**Compatibility notes:**
- `app::run` and `app::EXIT_CONFIG` continue to work.
- `tests/app_baseline.rs` and `tests/app_inline_ignore.rs` exercise the
  binary end-to-end via `CARGO_BIN_EXE_slopguard`; no `slopguard::app`
  import.

## 2.2 `src/lib.rs`

**Current size:** 2 215 chars / 64 lines. **No split** — all rustdoc,
single `pub use` re-export of three engine types.

## 2.3 `src/rules/finding.rs` → add `src/rules/finding_wire.rs`

**Current size:** 13 521 chars / 409 lines.

**Top-level items:** `LineCol`, `Finding` (with 12 builder methods),
`OwnedCweRef` (pub(crate)), `FindingWire` (pub(crate)), the conversions
in both directions, `impl Deserialize for Finding`, two private serde
helpers.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `rules/finding.rs` (slimmed) | `LineCol`, `Finding`, the 12-method `impl Finding` builder. | ~7 700 |
| `rules/finding_wire.rs` (new) | `OwnedCweRef`, `FindingWire`, `From<Finding> for FindingWire`, `FindingWire::into_finding`, `impl Deserialize for Finding`, `serialize_optional_cwe`, `is_false`. | ~5 700 |

**Optional further split:** `rules/finding.rs` (struct + `new` + `fingerprint*` = ~4 000) + `rules/finding_builders.rs` (the `with_*` chain = ~3 500). Re-export `finding_builders` from `rules/mod.rs` if used externally (it is not today).

**`mod.rs` changes:** The current `pub use finding::{Finding, LineCol};` stays. The new `pub(crate) mod finding_wire;` is **not** re-exported (it is internal-only).

**Compatibility notes:** `Deserialize for Finding` is implemented on the
public `Finding` type; the trait's path is foreign, so the impl's
location doesn't matter for the public surface.

## 2.4 `src/rules/fingerprint.rs` (optional)

**Current size:** 3 235 chars / 107 lines.

**Recommendation: leave as-is.** If a split is required:
- `rules/fingerprint.rs` (slim) — `Fingerprint`, `FingerprintParseError`, `impl Display` (~1 500).
- `rules/fingerprint_parse.rs` (new) — `impl Fingerprint` body for `parse` + `parse_usize` + `normalize_file_path` (~1 700).

## 2.5 `src/rules/emit.rs` (optional)

**Current size:** 2 165 chars / 96 lines.

**Recommendation: leave as-is.** Optional split:
- `rules/emit.rs` (slim) — `push_finding` + `rule_meta` (~1 100).
- `rules/emit_helpers.rs` (new) — `push_finding_with_evidence` + `push_finding_with_snippet` (~1 100).

## 2.6 `src/reporting/sarif.rs` → `src/reporting/sarif/`

**Current size:** 12 062 chars / 378 lines.

**Top-level items:** 5 constants, 14 `Sarif*` DTO structs, `print`,
`print_compact`, `print_with`, `build_log` (~140 lines), `iso8601_utc_now`,
`unix_epoch_to_ymdhms`, `render_to_string`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `sarif/mod.rs` | `mod` decls + `pub use entry::{print, print_compact, render_to_string};` | ~300 |
| `sarif/schema.rs` | The 14 `Sarif*` DTO structs + 5 constants. | ~4 500 |
| `sarif/log.rs` | `build_log` (largest single function). | ~5 000 |
| `sarif/entry.rs` | `print` / `print_compact` / `print_with` / `render_to_string`. | ~1 000 |
| `sarif/time.rs` | `iso8601_utc_now` + `unix_epoch_to_ymdhms` (orthogonal helper). | ~1 500 |

**`log.rs` is ~5 KB** — the irreducible cost of the SARIF mapping logic.
Further micro-splitting (e.g. one file per severity mapping) is
over-engineering.

**Compatibility notes:** The 14 `Sarif*` DTOs are `pub` but
`#[doc(hidden)]`. No external test references them by name; the
schema split has zero external breakage.

## 2.7 `src/reporting/text.rs` → `src/reporting/text/`

**Current size:** 10 111 chars / 341 lines.

**Top-level items:** cfg-gated `mod style`, `print`, `print_without_snippet`,
`TextOptions`, `print_with_options`, `write_with_options` (~80 lines),
`evidence_summary`, `write_summary`, `write_detector_timing`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `text/mod.rs` | `mod` decls + `pub use options::{print, print_without_snippet, print_with_options, TextOptions}; pub use render::write_with_options;` | ~400 |
| `text/style.rs` | The two cfg-gated `mod style` blocks. | ~1 800 |
| `text/options.rs` | `TextOptions`, `print`, `print_without_snippet`, `print_with_options`. | ~1 100 |
| `text/render.rs` | `write_with_options` + `evidence_summary`. | ~3 700 |
| `text/summary.rs` | `write_summary` + `write_detector_timing`. | ~3 000 |

## 2.8 `src/reporting/json.rs` → `src/reporting/json/`

**Current size:** 5 315 chars / 170 lines.

**Top-level items:** `print`, `print_envelope`, private `print_ndjson`,
`Envelope`, `FindingJson`, `DisplayCweRef`, three `From` impls, `is_false`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `json/mod.rs` | `mod` decls + `pub use entry::{print, print_envelope}; pub use types::{Envelope, FindingJson, DisplayCweRef};` | ~300 |
| `json/entry.rs` | `print` + `print_envelope` + `print_ndjson`. | ~1 300 |
| `json/types.rs` | The DTO structs + From impls + `is_false`. | ~3 700 |

**Caveat:** `tests/reporting_json.rs` imports `Envelope` and
`FindingJson` by name. The re-export from `json/mod.rs` keeps the path
stable.

## 2.9 `src/export/mod.rs` → `src/export/`

**Current size:** 8 638 chars / 272 lines.

**Top-level items:** `ExportOptions`, `ExportSummary`, `export_findings`,
`format_finding_block`, `finding_context_lines`,
`write_chunk_files_streaming`, `clean_matching_txt_files`.

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `export/mod.rs` | `mod` decls + `pub use options::{ExportOptions, ExportSummary}; pub use entry::export_findings;` | ~300 |
| `export/options.rs` | `ExportOptions` + `ExportSummary`. | ~600 |
| `export/entry.rs` | `export_findings` (the dispatcher). | ~1 900 |
| `export/finding_block.rs` | `format_finding_block`. | ~2 700 |
| `export/context.rs` | `finding_context_lines`. | ~2 700 |
| `export/chunk.rs` | `write_chunk_files_streaming` + `clean_matching_txt_files`. | ~2 200 |

## 2.10 `src/cli/mod.rs` → `src/cli/`

**Current size:** 8 480 chars / 302 lines.

**Top-level items:** `Cli` struct (~150 lines of fields), `Command` enum,
`LangMode` enum + impl, `OutputFormat` enum, `RuleCategory` enum + impl,
`SeverityArgs` struct + impl, `impl Cli` (3 methods: `generate_baseline`,
`scan_context`, `export_options`).

**Proposed split:**

| New file | Contents | Approx chars |
|---|---|---:|
| `cli/mod.rs` | `mod` decls + `pub use args::Cli; pub use enums::{Command, LangMode, OutputFormat, RuleCategory}; pub use severity_args::SeverityArgs;` | ~400 |
| `cli/args.rs` | `Cli` struct (clap field list). | ~6 000 |
| `cli/args_impl.rs` | `impl Cli` (3 methods). | ~1 500 |
| `cli/enums.rs` | `Command`, `LangMode` (+impl), `OutputFormat`, `RuleCategory` (+impl). | ~1 700 |
| `cli/severity_args.rs` | `SeverityArgs` struct + impl. | ~1 100 |

**`cli/args.rs` is ~6 KB** — single declarative struct with no logic.
Further micro-splitting (one file per flag) is anti-pattern.

## 2.11 Doc & plan path updates

The following references are doc-only; update them as part of the PR:

| File | Line | Update |
|---|---|---|
| `docs/architecture-performance.md` | 53 | `src/app.rs` → `src/app/` (or `src/app/run.rs`) |
| `plans/v0.0.1/architecture-performance-enhancement/PR/pr-architecture-performance-enhancement-sprint.md` | 209 | same |
| `plans/p2-implementation/02-baseline-ignore.md` | 126 | `src/app.rs` → `src/app/run.rs` |
| `plans/v0.0.1/architecture-enchancement-2/Review2.md` | 65 | `sarif.rs:80-87` → `sarif/schema.rs` |
| `plans/v0.0.1/architecture-enchancement-2/MODULE_CLEANUP.md` | 65 | same |
| `plans/v0.0.1/architecture-performance-enhancement/PR/pr-implementation-summary-round2-2026-06-05.md` | 104 | same |

## 2.12 Recommended order of operations

1. **§2.2, 2.4, 2.5** — doc-only / optional.
2. **§2.6, 2.7, 2.8 `reporting/*`** — independent of `app.rs`.
3. **§2.9 `export/*`**.
4. **§2.10 `cli/*`**.
5. **§2.3 `rules/finding_wire.rs`** — additive, no public-API change.
6. **§2.1 `app/*`** — last, because `app.rs` is the most cross-referenced.
7. **Verification after each batch:** `cargo build && cargo test --test app_baseline --test app_inline_ignore --test reporting_text --test reporting_json --test reporting_sarif --test export`.

## 2.13 Compatibility audit (no test changes required)

| File | What it imports | Unchanged by split? |
|---|---|---|
| `src/main.rs` | `slopguard::cli::Cli; app::run; app::EXIT_CONFIG` | yes |
| `tests/cli_baseline.rs` | `slopguard::cli::Cli` | yes |
| `tests/engine_config.rs` | `slopguard::cli::{Cli, RuleCategory}` | yes |
| `tests/engine_observability.rs` | `slopguard::cli::Cli` | yes |
| `tests/engine_cache.rs` | `slopguard::cli::Cli` | yes |
| `tests/reporting_text.rs` | `slopguard::reporting::text::{TextOptions, write_with_options}` | yes |
| `tests/reporting_json.rs` | `slopguard::reporting::json::{Envelope, FindingJson}` | yes |
| `tests/reporting_sarif.rs` | `slopguard::reporting::sarif::render_to_string` | yes |
| `tests/export.rs` | `slopguard::export::{ExportOptions, export_findings}` | yes |
| `tests/engine_source_cache.rs` | `slopguard::export::{ExportOptions, export_findings}` | yes |
| `tests/app_baseline.rs` | `CARGO_BIN_EXE_slopguard` (no `slopguard::app` import) | yes |
| `tests/app_inline_ignore.rs` | same | yes |
