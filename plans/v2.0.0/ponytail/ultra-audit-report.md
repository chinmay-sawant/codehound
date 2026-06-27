# Slopguard — Ponytail Ultra-Audit Report

> **Generated:** 2026-06-27
> **Mode:** Ultra (maximum aggression — find everything questionable)
> **Scope:** Whole-repo scan via 6 parallel subagents
> **Net potential:** **~153 findings**, **~1,900–2,100 removable lines**, **0 deps removable**

---

## Executive Summary

The codebase is lean for its capability. The biggest wins are: (1) **~580 lines** of dead/unused types and boilerplate in the rules/CWE layer, (2) **~600–800 lines** of test consolidation (duplicated helpers and mergeable test files), (3) **~205 lines** from eliminating 4 redundant hand-rolled ISO-8601 formatters in favor of the already-installed `jiff` crate. No dependencies can be removed — but many hand-rolls duplicate what the stdlib or existing deps cover.

---

## 1. Engine Core — `src/engine/{analyzer,cache,baseline}/`

**Targets:** 17 files | **Findings:** 26 | **~170 lines removable**

### Checklist

- [ ] `stdlib:` `hex_lower` hand-rolls hex encoding. Use `sha2` digest's `fmt::LowerHex` impl or `hex::encode`. [`hash.rs:20-28`]
- [ ] `yagni:` `CacheError::ToolVersionMismatch` variant never constructed. [`types.rs:96`]
- [ ] `yagni:` `CacheError::EntryMissing` variant never constructed. [`types.rs:98`]
- [ ] `yagni:` `CacheError::Corrupt` variant never constructed. [`types.rs:100`]
- [ ] `delete:` `iso8601_now()` is a trivial wrapper around `iso8601_utc_now()`. Re-export the inner fn. [`hash.rs:33-35`]
- [ ] `native:` `CacheStore::read_entry()` delegates to `store_lifecycle::read_entry`. Remove method, call free fn directly. [`store_open.rs:153-155`]
- [ ] `shrink:` `CacheStore::cache_dir()` getter — make field `pub(super)`. [`store_open.rs:87-89`]
- [ ] `shrink:` `CacheStore::files_dir()` getter — make field `pub(super)`. [`store_lifecycle.rs:139-141`]
- [ ] `yagni:` `is_cache_hit()` only used in tests. Move to `#[cfg(test)]`. [`store_open.rs:135-137`]
- [ ] `shrink:` `CacheStore::open()` is a wrapper around `open_with_capacity(dir, 0)`. Callers can call `open_with_capacity` directly. [`store_open.rs:19-21`]
- [ ] `shrink:` `CacheManifest.cache_dir` persisted to JSON but never read back. Delete it. [`types.rs:25`]
- [ ] `shrink:` `CacheStore::manifest()` getter — move to `#[cfg(test)]`. [`store_open.rs:149-151`]
- [ ] `stdlib:` `iso8601_utc_now` duplicated in `cache/hash.rs:37` and `baseline/io.rs:29`. Reuse from one place. [`baseline/io.rs:29-36`]
- [ ] `stdlib:` `unix_epoch_to_ymdhms` duplicated in `cache/hash.rs:54` and `baseline/io.rs:38`. Move to shared utility. [`baseline/io.rs:38-63`]
- [ ] `shrink:` `evict_to_size()` rewrites metadata that `flush()` also writes. Remove duplicate write from `evict_to_size()`. [`store_flush.rs:79-90`]
- [ ] `yagni:` `Baseline::contains()` and `contains_finding()` have near-identical logic. Remove `contains`, rewrite tests. [`baseline/store.rs:73-101`]
- [ ] `yagni:` Type-state pattern on `AnalyzerBuilder` (~50 lines). Replace with single builder + default `LanguageFilter::All`. [`builder.rs:15-98`]
- [ ] `yagni:` `AnalyzerBuilder.registry: Option<Registry>` always uses `Registry::default()`. Drop the `Option`. [`builder.rs:21,110`]
- [ ] `delete:` `go_module_prefix` computed eagerly in `build()` but recomputed in `scan.rs:57`. Remove from `build()`. [`builder.rs:108`]
- [ ] `delete:` `Analyzer::builder()` delegates to `AnalyzerBuilder::new()`. Inline at single usage. [`builder.rs:123-125`]
- [ ] `shrink:` `Analyzer::scan_context()` getter — make `ctx` field `pub`. [`types.rs:27-29`]
- [ ] `yagni:` `Analyzer::analyze_paths` uses complex generic `I: IntoIterator<Item=P>`. Take `&[impl AsRef<Path>]`. [`scan.rs:34-52`]
- [ ] `shrink:` `write_atomic` serializes to `String` then `write_all`. Use `serde_json::to_writer_pretty` directly. [`io.rs:32-33`]
- [ ] `shrink:` `CacheStore` impl blocks split across 3 files (~462 lines). Merge into one file. [`store_flush.rs`, `store_lifecycle.rs`, `store_open.rs`]

---

## 2. Engine Support — `src/engine/{walk,config,dependencies,diagnostics,ignore,stats,timing,...}/`

**Targets:** 42 files | **Findings:** 20 | **~180 lines removable**

### Checklist

- [ ] `delete:` `ScanOutcome::Cached` has unused `language: LanguageId` field with `#[expect(dead_code)]`. Delete field. [`walk/parallel.rs:53`]
- [ ] `delete:` `scan_err` function duplicated in `walk/scan_entry.rs:23-28` and `walk/parallel.rs:124-130`. Deduplicate. [`walk/scan_entry.rs:23-28`]
- [ ] `delete:` `dependencies/entry.rs:68-70` trivial `extensions` wrapper. Rename `extensions_for` and drop wrapper. [`dependencies/entry.rs:11-18`]
- [ ] `delete:` `walk/scan_entry.rs:252-254` dead `if spans.is_empty()` — always false. [`walk/scan_entry.rs:252-254`]
- [ ] `delete:` `timing/millis.rs:11-15` `deserialize` function dead code. [`timing/millis.rs:11-15`]
- [ ] `delete:` `config/section.rs:25-27` `SlopguardConfig::discover()` never called. [`config/section.rs:25`]
- [ ] `delete:` `stats/file.rs:7` `skipped: bool` field always `false`, never read. [`stats/file.rs:7`]
- [ ] `delete:` `stats/scan.rs:111-126` `record_skipped`, `record_cache_hit`, `record_cache_miss` never called. [`stats/scan.rs:111-126`]
- [ ] `yagni:` `config/section.rs:53-107` — 11 accessor methods on `SlopguardConfig` for pub fields. Remove, callers access directly. [`config/section.rs:53-107`]
- [ ] `yagni:` `config/types.rs:50-57,81-89,107-114` — manual `Default` impls for config structs. `#[serde(default)]` already provides it. [`config/types.rs:50`]
- [ ] `yagni:` `walk/analyze.rs:44-55` throwaway `TimingCollector::new(false)`. Call with `None` directly. [`walk/analyze.rs:44-55`]
- [ ] `shrink:` `walk/parallel.rs:428-433` `bytecount_lines` — empty-string guard unnecessary, `s.lines().count()` returns 0. [`walk/parallel.rs:428-433`]
- [ ] `shrink:` `walk/parallel.rs:161` discarded `suppressed` value. Use or remove computation. [`walk/parallel.rs:161`]
- [ ] `shrink:` `diagnostics/build.rs:49-69` — 5 near-identical severity-count blocks. Replace with loop over `Severity::variants()`. [`diagnostics/build.rs:49-69`]
- [ ] `shrink:` `ignore/apply.rs` — `" (suppressed)"` appended in 2 places. Extract helper. [`ignore/apply.rs:31`]
- [ ] `shrink:` `ignore/parse.rs:34-51` — shared prefix extraction in 2 functions. Extract `fn comment_body`. [`ignore/parse.rs:34-51`]
- [ ] `shrink:` `config/discover.rs:15-57` — shared walking loop in 2 functions. Extract `walk_up(start, predicate)`. [`config/discover.rs:15-57`]
- [ ] `shrink:` `timing/summary.rs:16-52` `TimingSummary::merge` duplicates logic from `TimingCollector::to_summary`. Share it. [`timing/summary.rs:16`]
- [ ] `shrink:` 3 functions share file-read-to-UTF-8 logic. Extract `read_utf8(path)` helper. [`dependencies/entry.rs:11`, `walk/scan_entry.rs:46-73`, `walk/parallel.rs:132-148`]
- [ ] `yagni:` `LanguageId::TypeScript` variant with `#[cfg(feature = "typescript")]` — feature exists in Cargo.toml but empty match arm. Speculative. [`dependencies/entry.rs:15`]

---

## 3. Language Support — `src/lang/{go,python}/`, `src/ast/`, `src/fixture/`

**Targets:** ~30 files | **Findings:** 14 | **~175 lines removable**

### Checklist

- [ ] `delete:` `src/lang/go/detectors/facts.rs` — entire orchestrator is dead code. Neither CWE nor PERF calls `build_go_facts`. [`facts.rs:1-70`]
- [ ] `delete:` `src/lang/go/function_kinds.rs` — 2-element const in its own file. Inline into `mod.rs`. [`function_kinds.rs:1-9`]
- [ ] `delete:` `src/lang/go/loop_kinds.rs` — 1-element const in its own file. Inline into `mod.rs`. [`loop_kinds.rs:1-6`]
- [ ] `delete:` `src/lang/python/loop_kinds.rs` — 2-element const. Inline into `mod.rs`. [`loop_kinds.rs:1-3`]
- [ ] `delete:` `src/lang/python/matchers.rs` — 1-line fn used once. Inline into `re_compile_in_loop.rs`. [`matchers.rs:1-8`]
- [ ] `shrink:` Go/Python parsers are ~90% identical. Extract shared parser helper under `src/lang/`. [`go/parser.rs`, `python/parser.rs`]
- [ ] `shrink:` Go/Python plugin impls are identical delegation. Make data-driven from enum or macro. [`go/mod.rs:16-48`, `python/mod.rs:14-44`]
- [ ] `shrink:` `enabled_plugins()` uses 4 cfg blocks for 2 features. Simplify with 2 `#[cfg]` pushes. [`mod.rs:12-29`]
- [ ] `shrink:` `walk_calls_and_assignments` has 6 Go-specific node kinds in shared `ast`. Move to Go plugin. [`ast/walk.rs:34-58`]
- [ ] `shrink:` `try_record_function_span` requires post-processing in caller. Accept `line_starts` and compute inline. [`ast/function/collect.rs:72-89`]
- [ ] `stdlib:` `FixtureLanguage::parse()` hand-rolled. Implement `FromStr` trait instead. [`fixture/format.rs:19-26`]
- [ ] `yagni:` `LanguagePlugin` trait with 2 impls behind `Box<dyn>`. Replace with enum + match. [`core/language/plugin.rs:11-51`]
- [ ] `yagni:` `GoCweScan` and `GoPerfScan` duplicate identical `Detector` boilerplate. Use macro. [`go/detectors/cwe/mod.rs:32-61`, `go/detectors/perf/mod.rs:36-62`]
- [ ] `yagni:` Python plugin `function_node_kinds` returns `&[]`. Implement or remove trait default. [`python/mod.rs:42-44`]

---

## 4. Rules / CWE / Core — `src/rules/`, `src/cwe/`, `src/core/`, `src/error.rs`

**Targets:** 28 files | **Findings:** 44 | **~580 lines removable**

### Checklist

- [ ] `delete:` `Fingerprint::parse()` — never called. [`fingerprint.rs:48`]
- [ ] `delete:` `FingerprintParseError` — only constructed by dead `parse()`. [`fingerprint.rs:26`]
- [ ] `delete:` `FingerprintParseError` in `error.rs` — dead variant. [`error.rs:18`]
- [ ] `delete:` `with_confidence()` builder — never called. [`finding.rs:197`]
- [ ] `delete:` `with_tags()` builder — never called. [`finding.rs:202`]
- [ ] `delete:` `with_remediation()` builder — never called. [`finding.rs:207`]
- [ ] `delete:` `mark_suppressed()` builder — never called. [`finding.rs:212`]
- [ ] `delete:` `with_byte_range()` builder — never called. [`finding.rs:218`]
- [ ] `delete:` `with_end()` builder — never called. [`finding.rs:225`]
- [ ] `delete:` `with_function_range()` builder — never called. [`finding.rs:234`]
- [ ] `delete:` `CWE_405` constant — dead, `#[expect(dead_code)]`. [`consts.rs:17`]
- [ ] `delete:` `CWE_1041` constant — dead, `#[expect(dead_code)]`. [`consts.rs:45`]
- [ ] `delete:` `DetectorKind::FactDriven` variant — never matched. [`detector_kind.rs:9`]
- [ ] `delete:` `ControlFlowKind::DeferInLoop` — never constructed. [`evidence.rs:54`]
- [ ] `delete:` `ControlFlowKind::MissingErrorCheck` — never constructed. [`evidence.rs:55`]
- [ ] `delete:` `DetectorEvidence::PatternMatch` — never constructed. [`evidence.rs:11`]
- [ ] `delete:` `DetectorEvidence::MissingConfig` — never constructed. [`evidence.rs:25`]
- [ ] `delete:` `DetectorEvidence::Other` — never constructed. [`evidence.rs:33`]
- [ ] `delete:` `Finding::tags` field — always `None`. [`finding.rs:138`]
- [ ] `delete:` `Finding::confidence` field — always `None`. [`finding.rs:135`]
- [ ] `delete:` `Finding::remediation` field — always `None`. [`finding.rs:144`]
- [ ] `delete:` `Finding::end_line/end_column` — always `None`, plus 7 sibling always-None fields. [`finding.rs:94-117`]
- [ ] `delete:` `RuleDescription::original_description` — deserialized but never read. [`description.rs:35`]
- [ ] `yagni:` `RuleId` newtype — turns into `&str` at every use. Just use `&str`. [`types.rs:7`]
- [ ] `yagni:` `FilePath` newtype — thin `String` wrapper, emit fns already take `&str`. [`types.rs:35`]
- [ ] `yagni:` `Fingerprint.tool/version` fields — always same values. Hardcode in `Display`/`parse`. [`fingerprint.rs:17-18`]
- [ ] `yagni:` `DetectorKind` enum — single variant (`Heuristic`) in active use. [`detector_kind.rs:4`]
- [ ] `stdlib:` `normalize_file_path()` — 1-line `file.replace('\\', "/")`. Inline. [`fingerprint.rs:98`]
- [ ] `stdlib:` `parse_usize()` — 5-line `str::parse()` wrapper. Inline. [`fingerprint.rs:102`]
- [ ] `shrink:` `push_finding` / `push_finding_with_evidence` / `push_finding_with_snippet` — three near-identical functions. Merge into one. [`emit.rs:8-77`]
- [ ] `shrink:` `push_finding_with_evidence` and `push_finding_with_snippet` duplicate `meta.fix` block. Hoist to shared helper. [`emit.rs:47-49, 73-75`]
- [ ] `shrink:` `collect_stats()` and `collect_detector_timing()` — identical body. One method. [`context.rs:79-86`]
- [ ] `shrink:` `filter.rs` — 11-line module with one function used only by `context.rs`. Inline. [`filter.rs:1-11`]
- [ ] `shrink:` `cwe/helpers.rs` — 3-line re-export file. Merge into `cwe/mod.rs`. [`helpers.rs:1-3`]
- [ ] `shrink:` `format_cwe()` — `impl Display` via private `W` struct. Use `format!("CWE-{id}")`. [`mod.rs:23-31`]
- [ ] `shrink:` `rule_meta()` const fn — wrapper around struct literal. Callers write `RuleMetadata{…}` directly. [`emit.rs:80-96`]
- [ ] `shrink:` `LanguageId::from_config_name()` — `to_lowercase()` allocates. Use `eq_ignore_ascii_case`. [`id.rs:25`]
- [ ] `shrink:` `GrammarError` — separate type + `From` impl wrapping to `Error::Grammar`. Use `Error::Grammar` directly. [`error.rs:37-47`]
- [ ] `shrink:` `deserialize_id()` — custom deserializer. Replace with `#[serde(untagged)]` helper enum. [`description.rs:14-24`]
- [ ] `shrink:` `FindingWire` — 194-line mirror of `Finding` with field-by-field `From`/`into_finding`. Use shared struct or macro. [`finding_wire.rs:1-194`]
- [ ] `shrink:` `serialize_optional_cwe` — custom serializer. `#[serde(default)]` with `Vec<CweRef>` works. [`finding.rs:23-31`]

---

## 5. Reporting / Export / App / CLI — `src/reporting/`, `src/export/`, `src/app/`, `src/cli/`

**Targets:** 34 files | **Findings:** 15 | **~205 lines removable**

### Checklist

- [ ] `stdlib:` 4 copies of `iso8601_utc_now` + `unix_epoch_to_ymdhms` (~40 lines each). `jiff = "0.2"` is already a dep — replace all with `jiff::Timestamp::now().strftime(…)`. [`sarif/time.rs:6-40`, `diagnostics/clock.rs`, `baseline/io.rs`, `cache/hash.rs`]
- [ ] `delete:` `print_without_snippet` — `pub` re-exported but never called outside `reporting/text/`. [`reporting/text/options.rs:34`]
- [ ] `delete:` `write_with_options` — `pub` re-exported but only called internally. [`reporting/text/mod.rs:9`]
- [ ] `delete:` `DisplayCweRef` — `pub` re-export from `reporting::json` never imported elsewhere. [`reporting/json/mod.rs:12`]
- [ ] `delete:` `render_to_string` — `pub` but only integration tests use it. Mark `pub(crate)`. [`reporting/sarif/entry.rs:45`]
- [ ] `delete:` `TOOL_NAME`, `TOOL_VERSION`, `TOOL_URI` — each used once. Inline literals. [`reporting/sarif/schema.rs:10-12`]
- [ ] `delete:` `--warnings-as-errors` flag has no effect — `fail_policy()` always returns `MediumAsErrors`. [`cli/severity_args.rs:12`]
- [ ] `yagni:` `json/entry.rs::print()` delegates to `print_ndjson()` unchanged. Rename or inline. [`reporting/json/entry.rs:16-18`]
- [ ] `yagni:` `sarif/entry.rs::print()` and `print_compact()` — thin wrappers around `print_with(result, bool)`. Collapse callers. [`reporting/sarif/entry.rs:16-28`]
- [ ] `yagni:` `app/cache.rs::cache_rebuild_dir()` — pure delegation to `cache_directory()`. Delete, callers use that. [`app/cache.rs:51-53`]
- [ ] `yagni:` `cli/args_impl.rs::generate_baseline()` — trivial getter on `pub` field. [`cli/args_impl.rs:11-13`]
- [ ] `shrink:` `SarifSuppression` — 1-field struct. Replace with `&'static str` in Vec. [`reporting/sarif/schema.rs:94-98`]
- [ ] `shrink:` `Envelope` and `FindingJson` — `pub` + `#[doc(hidden)]`. Should be `pub(crate)` or private. [`reporting/json/types.rs:15,50`]

---

## 6. Tests — `tests/`

**Targets:** 72 files | **Findings:** 34 | **~600–800 lines removable**

### Checklist

- [ ] `yagni:` `collect_cases_with_suffix` duplicated in `go_cwe_cases.rs:46` and `go_perf_cases.rs:35`. Move to shared helper.
- [ ] `shrink:` `assert_fixture_rules` and `assert_fixture_rules_with_context` share 90% body. Take analyzer as param. [`helpers/mod.rs:46`]
- [ ] `shrink:` `assert_fixture_materializes` path checks duplicated inside `assert_fixture_rules`. Let caller call both. [`helpers/mod.rs:18`]
- [ ] `delete:` `assert_fixture_rules_with_context` — only used by one caller. Inline it. [`helpers/mod.rs:89`]
- [ ] `delete:` `FindingStub` struct — used in one file. Move there. [`helpers/baseline.rs:5`]
- [ ] `yagni:` `parse_findings` helper — only used by `app_baseline_filter.rs`. Move inline. [`helpers/baseline.rs:72`]
- [ ] `yagni:` `unique_temp_root` duplicated in `cache.rs:8`, `inline_ignore.rs:5`, `baseline.rs:17`. Make one.
- [ ] `shrink:` `reporting.rs` — 5 factory functions differing only in fields. Replace with `sample_result(findings: Vec<Finding>)`. [`helpers/reporting.rs:9`]
- [ ] `shrink:` `write_minimal_go` (cache.rs) and `write_vulnerable_go` (inline_ignore.rs) — both embedded Go source helpers. Unify.
- [ ] `shrink:` `finding()` factory in `cache.rs:35` unused by rules tests which re-create boilerplate 40×. Import it.
- [ ] `yagni:` `TempProject.write_python_finding` — `pattern_name` param always `"item"` or `"other"`. Remove it. [`helpers/baseline.rs:42`]
- [ ] `yagni:` `dep_helpers::unique_root` in `cache.rs:57` duplicates `unique_temp_root` from same file.
- [ ] `shrink:` Hand-rolled `iso8601_from_secs` used once in `reporting_sarif_core.rs:6`. Replace with `jiff`.
- [ ] `shrink:` `rules_finding_construction.rs`, `rules_finding_serialization.rs`, `rules_finding_structured.rs` — 3 files testing same type. Merge into 1. [`rules_finding_construction.rs:8`]
- [ ] `shrink:` `fingerprint_is_stable_across_calls` tested in both `rules_finding_structured.rs:6` and `rules_fingerprint.rs:18`. Delete one.
- [ ] `shrink:` `rules_evidence.rs` — 4 serialize-deserialize tests. Data-driven table test in 15 lines. [`rules_evidence.rs:6`]
- [ ] `shrink:` `rules_severity.rs` — 5 tests for 5-variant enum. 1 test with a loop. [`rules_severity.rs:4`]
- [ ] `shrink:` `engine_sinks.rs` — 4 tests all calling `matches_sink`. 1 data-driven test. [`engine_sinks.rs:4`]
- [ ] `shrink:` `engine_cache_scan.rs` — cache config tests belong in `engine_config_parsing.rs`. Move them. [`engine_cache_scan.rs:144`]
- [ ] `shrink:` `engine_cache_store.rs` and `engine_cache_scan.rs` both `#[cfg(feature = "go")]`. Merge into 1 file. [`engine_cache_store.rs:1`]
- [ ] `shrink:` `engine_source_cache_populate.rs` — 4 tests, last 3 add little. Keep 1, delete 3. [`engine_source_cache_populate.rs:11`]
- [ ] `yagni:` `no_cache_cli_flag_is_parsed_and_wired` — tests a `clap::Parser` round-trip. Already covered by CLI unit tests. [`engine_cache_scan.rs:110`]
- [ ] `shrink:` `engine_observability_*.rs` (context, diagnostics, timing) — 3 files, 7 tests < 200 lines. Merge into 1.
- [ ] `shrink:` `reporting_sarif_*.rs` (core, region, snapshot, structured) — 4 files for 1 output format. Merge into 1-2.
- [ ] `shrink:` `reporting_json_*.rs` (cwe_ndjson, envelope, envelope_snapshot, finding) — 4 files. Merge into 2.
- [ ] `yagni:` `engine_config_parsing.rs` and `engine_config_merge.rs` — both < 200 lines, both test config parsing/merging. Merge.
- [ ] `shrink:` 4 inline-ignore test files (cache, engine, app 2×). Reduce to 2.
- [ ] `yagni:` 6 Go detector internal test files (< 100 lines each). Merge into 2.
- [ ] `yagni:` `engine_cache_debug.rs` — 2 `#[ignore]`d tests hardcoding `/home/chinmay/...`. Delete. [`engine_cache_debug.rs:6`]
- [ ] `shrink:` `export.rs` — `Box::leak(Box::new([…]))` pattern for `&'static CweRef`. Use `CweRef::leaked(…)` once. [`export.rs:22`]
- [ ] `shrink:` `rules_emit.rs` — 4 tests constructing `meta_with_cwe()` then calling `push_finding*()`. 1 data-driven test. [`rules_emit.rs:17`]
- [ ] `shrink:` `Finding::new(FindingInputs::new(…))` boilerplate appears ~40× with same args. One `default_finding(rule)` helper. [`rules_finding_construction.rs:8`]

---

## Summary Totals

| Area | Findings | Lines Removable | Files Removable |
|---|---|---|---|
| 1. Engine Core | 26 | ~170 | 0 |
| 2. Engine Support | 20 | ~180 | 0 |
| 3. Language Support | 14 | ~175 | 5 |
| 4. Rules/CWE/Core | 44 | ~580 | 0 |
| 5. Reporting/Export/App/CLI | 15 | ~205 | 0 |
| 6. Tests | 34 | ~600–800 | 12–15 |
| **Total** | **153** | **~1,910–2,110** | **17–20** |

### Top 5 biggest wins

1. **`jiff`-ify ISO-8601** — 4 redundant hand-rolled date formatters (~160 lines) → one shared `jiff` call (area 5)
2. **Dead rules/CWE types** — 44 findings, ~580 lines of dead variants, unused builders, newtype wrappers (area 4)
3. **Test consolidation** — 34 findings, ~600–800 lines, 12–15 files merged or deleted (area 6)
4. **Engine support dedup** — 20 findings, ~180 lines of duplicated loops, dead stats methods (area 2)
5. **Language plugin dedup** — 14 findings, ~175 lines of duplicated parsers, dead facts file, standalone const files (area 3)

### Ponytail: skipped items

- `LanguagePlugin` trait → enum: ~50 loc saved, harder to extend. Add when 3rd language arrives.
- `FindingWire` – `Finding` merge: ~100 loc saved, possible schema risk. Keep FindingWire as a migration layer.
- Full test file merging: low-ROI mechanical work. Tackle during codebase restructure in v2.0.0.

> **Lean already check:** No dependencies removable. Core engine and detector logic are appropriately sized. The bloat is concentrated in: (a) dead API surface from iterative building, (b) duplicated test patterns, (c) hand-rolled stdlib routines in the presence of `jiff`.
