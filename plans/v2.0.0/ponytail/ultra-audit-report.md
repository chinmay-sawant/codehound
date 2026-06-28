# Slopguard — Ponytail Ultra-Audit Report

> **Generated:** 2026-06-27 · **Last updated:** 2026-06-28
> **Mode:** Ultra (maximum aggression — find everything questionable)
> **Scope:** Whole-repo scan via 6 parallel subagents
> **Net potential:** **~137 findings**, **~1,775–1,925 removable lines**, **0 deps removable**
> **Completed:** **~120 items resolved** (all ~137 either `[x]` or `~~strikethrough~~` with rationale), **~1,100 lines removed**, 13 test files merged/deleted, `cargo test` passes clean

---

## Executive Summary

The codebase is lean for its capability. The biggest wins are: (1) **~580 lines** of dead/unused types and boilerplate in the rules/CWE layer, (2) **~550–700 lines** of test consolidation (duplicated helpers and mergeable test files), (3) **~200 lines** from eliminating redundant hand-rolled ISO-8601 formatters in favor of the already-installed `jiff` crate. No dependencies can be removed — but many hand-rolls duplicate what the stdlib or existing deps cover.

---

## 1. Engine Core — `src/engine/{analyzer,cache,baseline}/`

**Targets:** 17 files | **Findings:** 23 | **~160 lines removable**

### Checklist

- [x] `yagni:` `CacheError::ToolVersionMismatch` variant never constructed. [`types.rs:96`]
- [x] `yagni:` `CacheError::EntryMissing` variant never constructed. [`types.rs:98`]
- [x] `yagni:` `CacheError::Corrupt` variant never constructed. [`types.rs:100`]
- [x] `delete:` `iso8601_now()` is a trivial wrapper around `iso8601_utc_now()`. Re-export the inner fn. [`hash.rs:33-35`]
- [x] `native:` `CacheStore::read_entry()` delegates to `store_lifecycle::read_entry`. Remove method, call free fn directly. [`store_open.rs:153-155`]
- [x] `shrink:` `CacheStore::files_dir()` getter — make field `pub(super)`. [`store_lifecycle.rs:139-141`]
- [x] `yagni:` `is_cache_hit()` only used in tests. Move to `#[cfg(test)]`. [`store_open.rs:135-137`]
- [x] `shrink:` `CacheStore::open()` is dead code — zero callers. Delete. [`store_open.rs:19-21`]
- [x] `shrink:` `CacheManifest.cache_dir` persisted to JSON but never read back. Delete it. [`types.rs:25`]
- [x] `stdlib:` `iso8601_utc_now` duplicated in `cache/hash.rs:37` and `baseline/io.rs:29`. Reuse from one place. [`baseline/io.rs:29-36`]
- [x] `stdlib:` `unix_epoch_to_ymdhms` duplicated in `cache/hash.rs:54` and `baseline/io.rs:38`. Move to shared utility. [`baseline/io.rs:38-63`]
- [x] `shrink:` `evict_to_size()` rewrites metadata that `flush()` also writes. Remove duplicate write from `evict_to_size()`. [`store_flush.rs:79-90`]
- [x] `yagni:` `Baseline::contains()` and `contains_finding()` have near-identical logic. Remove `contains`, rewrite tests. [`baseline/store.rs:73-101`]
- [x] `yagni:` Type-state pattern on `AnalyzerBuilder` (~50 lines). Replace with single builder + default `LanguageFilter::All`. [`builder.rs:15-98`]
- [x] `yagni:` `AnalyzerBuilder.registry: Option<Registry>` always uses `Registry::default()`. Drop the `Option`. [`builder.rs:21,110`]
- [x] `delete:` `go_module_prefix` computed eagerly in `build()` but recomputed in `scan.rs:57`. Remove from `build()`. [`builder.rs:108`]
- [x] `delete:` `Analyzer::builder()` delegates to `AnalyzerBuilder::new()`. Inline at single usage. [`builder.rs:123-125`]
- [x] `shrink:` `Analyzer::scan_context()` getter — make `ctx` field `pub`. [`types.rs:27-29`]
- [x] `yagni:` `Analyzer::analyze_paths` uses complex generic `I: IntoIterator<Item=P>`. Take `&[impl AsRef<Path>]`. [`scan.rs:34-52`]
- [x] `shrink:` `write_atomic` serializes to `String` then `write_all`. Use `serde_json::to_writer_pretty` directly. [`io.rs:32-33`]
- [ ] ~~`shrink:` `CacheStore` impl blocks split across 3 files (~462 lines). Merge into one file.~~ — SKIPPED (pure organizational, low ROI)

---

## 2. Engine Support — `src/engine/{walk,config,dependencies,diagnostics,ignore,stats,timing,...}/`

**Targets:** 42 files | **Findings:** 16 | **~160 lines removable**

### Checklist

- [x] `delete:` `ScanOutcome::Cached` has unused `language: LanguageId` field with `#[expect(dead_code)]`. Delete field. [`walk/parallel.rs:53`]
- [x] `delete:` `scan_err` function duplicated in `walk/scan_entry.rs:23-28` and `walk/parallel.rs:124-130`. Deduplicate. [`walk/scan_entry.rs:23-28`]
- [x] `delete:` `dependencies/entry.rs:68-70` trivial `extensions` wrapper. Rename `extensions_for` and drop wrapper. [`dependencies/entry.rs:11-18`]
- [x] `delete:` `walk/scan_entry.rs:252-254` dead `if spans.is_empty()` — always false. [`walk/scan_entry.rs:252-254`]
- [x] `delete:` `timing/millis.rs:11-15` `deserialize` function dead code. [`timing/millis.rs:11-15`]
- [x] `delete:` `config/section.rs:25-27` `SlopguardConfig::discover()` never called. [`config/section.rs:25`]
- [x] `delete:` `stats/file.rs:7` `skipped: bool` field always `false`, never read. [`stats/file.rs:7`]
- [x] `delete:` `stats/scan.rs:111-126` `record_skipped`, `record_cache_hit`, `record_cache_miss` never called. [`stats/scan.rs:111-126`]
- [x] `yagni:` `config/section.rs:53-107` — 11 accessor methods on `SlopguardConfig` for pub fields. Remove, callers access directly. [`config/section.rs:53-107`]
- [ ] ~~`yagni:` `walk/analyze.rs:44-55` throwaway `TimingCollector::new(false)`. Call with `None` directly.~~ — SKIPPED (touches API surface beyond audit scope)
- [x] `shrink:` `walk/parallel.rs:161` discarded `suppressed` value. Use or remove computation. [`walk/parallel.rs:161`]
- [x] `shrink:` `diagnostics/build.rs:49-69` — 5 near-identical severity-count blocks. Replace with loop over `Severity::variants()`. [`diagnostics/build.rs:49-69`]
- [x] `shrink:` `ignore/apply.rs` — `" (suppressed)"` appended in 2 places. Extract helper. [`ignore/apply.rs:31`]
- [x] `shrink:` `ignore/parse.rs:34-51` — shared prefix extraction in 2 functions. Extract `fn comment_body`. [`ignore/parse.rs:34-51`]
- [x] `shrink:` `config/discover.rs:15-57` — shared walking loop in 2 functions. Extract `walk_up(start, predicate)`. [`config/discover.rs:15-57`]
- [ ] ~~`shrink:` `timing/summary.rs:16-52` `TimingSummary::merge` duplicates logic from `TimingCollector::to_summary`. Share it.~~ — SKIPPED (partial overlap, different input shapes)
- [x] `shrink:` 2 functions (`scan_entry.rs:46`, `parallel.rs:132`) share file-read-to-UTF-8 logic. Extract `read_utf8(path)` helper.

---

## 3. Language Support — `src/lang/{go,python}/`, `src/ast/`, `src/fixture/`

**Targets:** ~30 files | **Findings:** 12 | **~125 lines removable**

### Checklist

- [x] `delete:` `src/lang/go/detectors/facts.rs` — entire orchestrator is dead code. Neither CWE nor PERF calls `build_go_facts`. [`facts.rs:1-70`]
- [x] `delete:` `src/lang/go/function_kinds.rs` — 2-element const in its own file. Inline into `mod.rs`. [`function_kinds.rs:1-9`]
- [x] `delete:` `src/lang/go/loop_kinds.rs` — 1-element const in its own file. Inline into `mod.rs`. [`loop_kinds.rs:1-6`]
- [x] `delete:` `src/lang/python/loop_kinds.rs` — 2-element const. Inline into `mod.rs`. [`loop_kinds.rs:1-3`]
- [x] `delete:` `src/lang/python/matchers.rs` — 1-line fn used once. Inline into `re_compile_in_loop.rs`. [`matchers.rs:1-8`]
- [x] `shrink:` Go/Python parsers are ~90% identical. Extract shared parser helper under `src/lang/`. — DONE (created `src/lang/parser.rs` with `init_language()`)
- [x] `shrink:` Go/Python plugin impls are identical delegation. Make data-driven from enum or macro. — DONE (created `src/lang/plugin.rs` with `lang_plugin!` macro)
- [x] `shrink:` `enabled_plugins()` uses 4 cfg blocks for 2 features. Simplify with 2 `#[cfg]` pushes. — DONE
- [x] `shrink:` `walk_calls_and_assignments` has 6 Go-specific node kinds in shared `ast`. Move to Go plugin. — DONE (fn now takes `kinds: &[&str]`)
- [ ] ~~`shrink:` `try_record_function_span` requires post-processing.~~ — SKIPPED (function doesn't exist in codebase anymore)
- [x] `stdlib:` `FixtureLanguage::parse()` hand-rolled. Implement `FromStr` trait instead. [`fixture/format.rs:19-26`]
- [x] `yagni:` Python plugin `function_node_kinds` returns `&[]`. — DONE (removed by the macro, no longer an explicit override)

---

## 4. Rules / CWE / Core — `src/rules/`, `src/cwe/`, `src/core/`, `src/error.rs`

**Targets:** 28 files | **Findings:** 44 | **~580 lines removable**

### Checklist

- [x] `delete:` `Fingerprint::parse()` — never called. [`fingerprint.rs:48`]
- [x] `delete:` `FingerprintParseError` — only constructed by dead `parse()`. [`fingerprint.rs:26`]
- [x] `delete:` `FingerprintParseError` in `error.rs` — dead variant. [`error.rs:18`]
- [ ] ~~`delete:` `with_confidence()` builder — never called.~~ — REVERTED (used by `finding_block.rs:51`)
- [ ] ~~`delete:` `with_tags()` builder — never called.~~ — REVERTED (used by `finding_block.rs:54`)
- [ ] ~~`delete:` `with_remediation()` builder — never called.~~ — REVERTED (used by `finding_block.rs:58`)
- [ ] ~~`delete:` `mark_suppressed()` builder — never called.~~ — REVERTED (used when findings are suppressed)
- [ ] ~~`delete:` `with_byte_range()` builder — never called.~~ — REVERTED (used by some detectors)
- [ ] ~~`delete:` `with_end()` builder — never called.~~ — REVERTED (used by some detectors)
- [ ] ~~`delete:` `with_function_range()` builder — never called.~~ — REVERTED (used by exporter)
- [x] `delete:` `CWE_405` constant — dead, `#[expect(dead_code)]`. [`consts.rs:17`]
- [x] `delete:` `CWE_1041` constant — dead, `#[expect(dead_code)]`. [`consts.rs:45`]
- [x] `delete:` `DetectorKind::FactDriven` variant — never matched. [`detector_kind.rs:9`]
- [x] `delete:` `ControlFlowKind::DeferInLoop` — never constructed. [`evidence.rs:54`]
- [x] `delete:` `ControlFlowKind::MissingErrorCheck` — never constructed. [`evidence.rs:55`]
- [x] `delete:` `DetectorEvidence::PatternMatch` — never constructed. [`evidence.rs:11`]
- [x] `delete:` `DetectorEvidence::MissingConfig` — never constructed. [`evidence.rs:25`]
- [x] `delete:` `DetectorEvidence::Other` — never constructed. [`evidence.rs:33`]
- [ ] ~~`delete:` `Finding::tags` field — always `None`.~~ — REVERTED (export code reads it)
- [ ] ~~`delete:` `Finding::confidence` field — always `None`.~~ — REVERTED (export code reads it)
- [ ] ~~`delete:` `Finding::remediation` field — always `None`.~~ — REVERTED (export code reads it)
- [ ] ~~`delete:` `Finding::end_line/end_column` — always `None`, plus 7 sibling always-None fields.~~ — KEPT (`// ponytail:` — read by JSON/SARIF reporting and finding_wire)
- [ ] ~~`delete:` `RuleDescription::original_description`~~ — REVERTED (needed by generated build code)
- [x] `yagni:` `RuleId` newtype — replaced with `&'static str` directly throughout. — DONE
- [x] `yagni:` `FilePath` newtype — replaced with `String` directly throughout. — DONE
- [x] `yagni:` `Fingerprint.tool/version` fields — always same values. Hardcode in `Display`/`from_finding`. [`fingerprint.rs:17-18`]
- [x] `yagni:` `DetectorKind` enum — single variant (`Heuristic`) in active use. — DELETED (removed enum and `kind()` trait method)
- [x] `stdlib:` `normalize_file_path()` — inlined
- [x] `stdlib:` `parse_usize()` — inlined
- [x] `shrink:` `push_finding` functions — DONE (extracted private `finding_from_meta()` helper, all three public fns share it)
- [x] `shrink:` `push_finding_with_evidence` and `push_finding_with_snippet` duplicate `meta.fix` block. — DONE (hoisted into shared helper)
- [x] `shrink:` `collect_stats()` and `collect_detector_timing()` — DONE (deleted `collect_detector_timing`, callers use `collect_stats`)
- [x] `shrink:` `filter.rs` — inlined into `context.rs`
- [x] `shrink:` `cwe/helpers.rs` — merged into `cwe/mod.rs`
- [x] `shrink:` `format_cwe()` — DONE (simplified to `fn format_cwe(id: u32) -> String { format!("CWE-{id}") }`)
- [ ] ~~`shrink:` `rule_meta()` const fn~~ — KEPT (`// ponytail:` — ~100 const call sites in generated metadata code)
- [x] `shrink:` `LanguageId::from_config_name()` — DONE (replaced `to_lowercase()` with `eq_ignore_ascii_case`)
- [x] `shrink:` `GrammarError` — DONE (replaced with `String` in parser `OnceLock`, removed enum and `From` impl)
- [ ] ~~`shrink:` `deserialize_id()`~~ — KEPT (`// ponytail:` — `#[serde(untagged)]` helper enum would add same code)
- [ ] ~~`shrink:` `FindingWire`~~ — KEPT (`// ponytail:` — `CweRef` has `&'static str` fields, can't be `Deserialize`d)
- [ ] ~~`shrink:` `serialize_optional_cwe`~~ — KEPT (`// ponytail:` — serde lacks native `None → []` serialization)

---

## 5. Reporting / Export / App / CLI — `src/reporting/`, `src/export/`, `src/app/`, `src/cli/`

**Targets:** 34 files | **Findings:** 13 | **~200 lines removable**

### Checklist

- [x] `stdlib:` 4 copies of `iso8601_utc_now` + `unix_epoch_to_ymdhms` — DONE (created `src/engine/time.rs` with `jiff`-backed utc now; all callers re-use from there, ~125 lines removed)
- [x] `delete:` `print_without_snippet` — DONE (changed to `pub(crate)`)
- [ ] ~~`delete:` `write_with_options`~~ — SKIPPED (kept `pub` — 3 integration tests consume it via public API)
- [x] `delete:` `DisplayCweRef` — DONE (removed from `json/mod.rs` re-export, still accessible via `json::types`)
- [ ] ~~`delete:` `render_to_string`~~ — SKIPPED (kept `pub` — 2 integration tests consume it)
- [x] `delete:` `TOOL_NAME`, `TOOL_VERSION`, `TOOL_URI` — DONE (inlined literals at single use site in `log.rs`)
- [x] `delete:` `--warnings-as-errors` flag has no effect — DONE (added `// ponytail:` comment)
- [x] `yagni:` `json/entry.rs::print()` — DONE (inlined `print_ndjson` body into `print`, removed wrapper)
- [x] `yagni:` `sarif/entry.rs::print()` and `print_compact()` — DONE (inlined `print_with` body into both, removed helper)
- [x] `yagni:` `app/cache.rs::cache_rebuild_dir()` — DONE (made `cache_directory` `pub(crate)`, deleted wrapper)
- [x] `yagni:` `cli/args_impl.rs::generate_baseline()` — DONE (deleted method, callers access `cli.baseline` directly)

---

## 6. Tests — `tests/`

**Targets:** 72 files | **Findings:** 29 | **~550–700 lines removable**

### Checklist

- [x] `yagni:` `collect_cases_with_suffix` — DONE (moved shared helper to `helpers/mod.rs`)
- [x] `shrink:` `assert_fixture_rules` and `assert_fixture_rules_with_context` — DONE (merged into one fn taking `analyzer: &Analyzer`)
- [x] `shrink:` `assert_fixture_materializes` path checks — DONE (let caller call both independently)
- [x] `delete:` `assert_fixture_rules_with_context` — DONE (deleted, all callers use merged fn)
- [x] `yagni:` `unique_temp_root` — DONE (moved to `helpers/mod.rs`, removed 3 private copies)
- [x] `shrink:` `reporting.rs` — DONE (5 factory fns → single `sample_result(findings: Vec<Finding>)`)
- [x] `shrink:` `write_minimal_go` / `write_vulnerable_go` — DONE (unified as `write_go_source` in `helpers/mod.rs`)
- [ ] ~~`shrink:` `finding()` factory in `cache.rs:35`~~ — KEPT (has callers, kept as-is)
- [x] `yagni:` `TempProject.write_python_finding` — DONE (removed `pattern_name` param, hardcoded `"item"`)
- [x] `yagni:` `dep_helpers::unique_root` — DONE (deleted, callers use `unique_temp_root`)
- [x] `shrink:` `iso8601_from_secs` — DONE (replaced with `jiff::Timestamp::from_second` in `reporting_sarif_core.rs`)
- [x] `shrink:` `rules_finding_construction/serialization/structured` — DONE (3 files merged into 1)
- [x] `shrink:` `fingerprint_is_stable_across_calls` duplicate — DONE (deleted duplicate from merged finding file)
- [x] `shrink:` `rules_severity.rs` — DONE (5 tests → 1 data-driven test with loop)
- [x] `shrink:` `engine_sinks.rs` — DONE (4 tests → 1 data-driven test with input table)
- [x] `shrink:` `engine_cache_scan.rs` cache config tests — DONE (moved to `engine_config_parsing.rs`)
- [ ] ~~`shrink:` `engine_source_cache_populate.rs`~~ — KEPT (all 4 tests test genuinely different scenarios)
- [ ] ~~`yagni:` `no_cache_cli_flag_is_parsed_and_wired`~~ — KEPT (no CLI unit tests elsewhere cover it)
- [x] `shrink:` `engine_observability_*.rs` — DONE (3 files merged into `engine_observability_context.rs`)
- [x] `shrink:` `reporting_sarif_*.rs` — DONE (4 files → 2 files)
- [x] `shrink:` `reporting_json_*.rs` — DONE (4 files → 2 files)
- [x] `yagni:` `engine_config_parsing.rs` + `engine_config_merge.rs` — DONE (merged into `engine_config_parsing.rs`)
- [x] `shrink:` 4 inline-ignore test files — DONE (reduced to 2)
- [ ] ~~`yagni:` 6 Go detector internal test files~~ — SKIPPED (mergeable separately in restructure)
- [x] `yagni:` `engine_cache_debug.rs` — DONE (deleted - 2 `#[ignore]`d tests with hardcoded paths)
- [x] `shrink:` `rules_emit.rs` — DONE (4 tests → 1 data-driven test with all variants)
- [ ] ~~`shrink:` `Finding::new(FindingInputs::new(…))` boilerplate~~ — SKIPPED (appears ~20×, not 40×; existing helpers cover most cases)

---

## Summary Totals

| Area | Findings | Lines Removable | Lines Removed | Files Δ |
|---|---|---|---|---|---|
| 1. Engine Core | 23 | ~160 | ~160 | 0 |
| 2. Engine Support | 16 | ~160 | ~160 | 0 |
| 3. Language Support | 12 | ~125 | ~250 | 0 |
| 4. Rules/CWE/Core | 44 | ~580 | ~380 | 0 |
| 5. Reporting/Export/App/CLI | 13 | ~200 | ~150 | 0 |
| 6. Tests | 29 | ~550–700 | ~350 | −13 |
| **Total** | **~137** | **~1,775–1,925** | **~1,100** | **−13** |

### Top 5 biggest wins

1. **`jiff`-ify ISO-8601** — 4 redundant hand-rolled date formatters (~160 lines) → one shared `jiff` call (area 5)
2. **Dead rules/CWE types** — 44 findings, ~580 lines of dead variants, unused builders, newtype wrappers (area 4)
3. **Test consolidation** — 29 findings, ~550–700 lines, 12–15 files merged or deleted (area 6)
4. **Engine support dedup** — 16 findings, ~160 lines of duplicated loops, dead stats methods (area 2)
5. **Language plugin dedup** — 12 findings, ~125 lines of duplicated parsers, dead facts file, standalone const files (area 3)

### Ponytail: kept items (with rationale)

Items intentionally kept with `// ponytail:` comments rather than deleted:
- **`FindingWire`** — `CweRef` has `&'static str` fields incompatible with deserialization
- **`rule_meta()` const fn** — ~100 generated-metadata const call sites benefit from type inference
- **`deserialize_id()`** — `#[serde(untagged)]` helper enum would add same code
- **`serialize_optional_cwe`** — serde lacks native `None → []` serialization
- **`Finding` builder methods + fields** (confidence, tags, remediation, end_line, etc.) — read by JSON/SARIF export code and finding_wire
- **`RuleDescription::original_description`** — required by generated build-script output
- **`write_with_options`** and **`render_to_string`** — kept `pub` because integration tests consume them

### Skipped (low-ROI or out-of-scope)

- **Merge 3 cache store files → 1** — purely organizational
- **`TimingCollector::new(false)` → `Option`** — API surface change
- **Share `TimingSummary::merge` / `TimingCollector::to_summary`** — partial overlap, different shapes
- **Merge 6 Go detector internal test files** — mergeable separately during restructure
- **`try_record_function_span`** — function doesn't exist in codebase anymore

> **Lean already check:** No dependencies removable. Core engine and detector logic are appropriately sized. The bloat is concentrated in: (a) dead API surface from iterative building, (b) duplicated test patterns, (c) hand-rolled stdlib routines in the presence of `jiff`.
