# Changelog

All notable changes to SlopGuard are documented in this file. Versions follow
[Semantic Versioning](https://semver.org/). Until 1.0.0, breaking changes are
expected every minor release; pin to a git revision or exact version.

## [Unreleased]

### Added
- `--json-envelope` flag (and `SLOPGUARD_JSON_ENVELOPE` env) that wraps the
  default text/JSON output in a machine-readable `Envelope` struct with
  `tool.version`, `schema`, `exit_code`, `findings[]`, and `errors[]`
- JSON `Envelope` output (NDJSON for SARIF, pretty for human-facing JSON)
  with `fingerprint` per finding
- `CweRef` serialised as `"CWE-N"` via a `DisplayCweRef` newtype so
  consumers see a stable string id instead of the internal u32
- `Finding` byte/end fields (`end_line`, `end_column`, `byte_offset`,
  `byte_length`) and helpers (`with_byte_range`, `with_end`, `fingerprint()`)
- SARIF `region.endLine` / `endColumn` / `byteOffset` / `byteLength` (and
  `partialFingerprints`) wired through the reporter
- `slopguard.schema.json` (JSON Schema draft-07, `additionalProperties: false`)
  with a unit test that verifies every field is described
- `ScanError` / `ScanErrorKind` derive `thiserror::Error` (replaces the
  hand-written `Display` impl) — source location preserved on every kind
- `catch_unwind` wrapper around `par_iter` in `scan_entries_parallel`;
  panics in one shard are converted to a typed `ScanError::Other` with a
  `panic_message` helper that handles `&'static str`, `String`, and other
  payloads
- In-process deterministic fuzz harness for the Go CWE facts builder
  (xorshift PRNG, 256 random byte sequences per `#[test]` run). The
  `fuzz/` `cargo-fuzz` scaffolding was removed — it required nightly and
  the same input distribution is now covered by a unit test on stable.
- GitHub Actions CI matrix (Linux + macOS, default/go/python features, MSRV 1.85)
- `cargo bench` smoke workflow
- `--config` flag and `SLOPGUARD_CONFIG` env var to override config discovery
- `SLOPGUARD_ONLY` / `SLOPGUARD_SKIP` env-var overrides
- `--list-rules` and `--explain <RULE>` subcommands
- `--init` writes a starter `slopguard.toml`
- `--quiet`, `--verbose`, `--no-snippet` flags
- `include` / `exclude` glob lists in `slopguard.toml`
- `.slopguardignore` support (added via `ignore::WalkBuilder`)
- Upward config walk (`discover_config`) — finds `slopguard.toml` in cwd or
  any parent
- Distinct exit codes: 0 clean, 1 failing findings, 2 config error,
  3 internal/IO error
- Per-file error reporting in `AnalysisResult.errors` (partial-failure
  recovery — one bad file no longer aborts the whole scan)
- SARIF 2.1.0 reporter now emits:
  - `tool.driver.informationUri`, `version`, `semanticVersion`
  - `runs[].invocations[].endTimeUtc`, `workingDirectory`,
    `executionSuccessful`
  - Per-result `ruleIndex`, `partialFingerprints`, `properties.tags`,
    `properties.security-severity`
  - Alphabetically sorted `rules[]` for stable diffs
- Text reporter now color-codes severity, sorts CWE list, and prints a
  per-severity / per-rule summary
- 22 new unit tests across `ast`, `rules`, `engine`, `reporting` modules
- 13 new unit tests for the Go CWE facts builder, JSON envelope mode, and
  scratch buffer (`scratch_contains`).

### Changed
- **Performance**: a further 15% faster scan of the 701-fixture corpus
  (`scan_materialized_fixtures`: 28.1 ms → 23.8 ms on top of last commit's
  32% win). The biggest wins this round came from:
  - `scratch_contains` thread-local buffer in `engine::walk`. 12 detector
    hot-paths that used `format!` to build a needle string now write into
    a per-rayon-worker `RefCell<String>` and `clear()` between calls —
    steady-state cost is zero allocations.
  - Fused `walk_calls_and_assignments` over the Go AST: the facts builder
    no longer walks the tree twice (once for calls, once for assignments);
    a single `walk` produces both fact kinds in one pass.
- `walk_assignments` + `walk_calls` AST walks are unchanged in count but the
  per-file line/col is now O(log N)
- `InputKind`, `InputBinding`, `CallFact`, `AssignmentFact`, `GoUnitFacts`,
  and `build_go_unit_facts` are now `pub(crate)` — the public
  `tests/go_cwe_facts_integration.rs` integration test was deleted in
  favour of `#[cfg(test)] mod tests` inside `facts.rs` (single build
  graph, no duplicate test compile cost)
- Caching `path.display().to_string()` on `ParsedUnit` (eliminates 175
  identical allocations per file)
- `Finding.cwe` is now `Option<Box<[CweRef]>>` so empty slices compile to
  a `None` with no heap allocation (was a 24-byte `Vec` header per
  finding for content that was always `&[]`)
- `line_col` is now O(log N) via a per-file `line_starts` table (was
  O(tree depth), called up to 175× per file)
- `SlopguardConfig` and `SlopguardSection` use `#[serde(deny_unknown_fields)]`
  — typos like `fali_on` now fail at parse time
- CLI severity policy is no longer overwritten by config's `fail_on` when
  the user passed `--strict` / `--no-fail` / `--warnings-as-errors` (CLI wins)
- `slopguard --format sarif --no-snippet` now emits compact JSON
- `materialized_root()` is per-process (no more race on `target/slopguard-fixtures/`
  between parallel test binaries)

### Fixed
- `detect_cwe_270`: explicit parens around `defer func() && WithValue` to
  remove ambiguity (was parsing as `A || (B && C)`; now explicit)
- `detect_cwe_841`: explicit parens around the `if MFAPassed && if !acct...`
  branch
- `detect_cwe_308`: skip emitting when the search needle isn't found instead
  of reporting at line 1, col 0
- `tests/config_languages_integration::go_only_filter_skips_python_files`
  was asserting on `SLOP00` prefix (no such rule); now correctly checks
  for `CWE-` Go findings
- Orphan-fixture check catches `.txt` files not listed in
  `tests/fixtures/manifest.toml`
- `target/slopguard-fixtures/` race between parallel test binaries
  (now per-process subdirectory)
- `let _ = Analyzer::builder().build();` dead expression in
  `fixture_manifest_integration::manifest_covers_default_languages` removed
- A panic inside any rayon shard during `scan_entries_parallel` is now
  caught and surfaced as a typed `ScanError` rather than tearing down
  the whole scan process

### Removed
- Dead `severity_threshold` function (`#[allow(dead_code)]` in
  `engine/config.rs`)
- Duplicate `all-langs` feature flag (was identical to `default`)
- `fuzz/` directory (the `cargo-fuzz` harness required nightly Rust).
  Coverage is preserved by an in-process deterministic random-input test
  in `facts.rs`.

## [0.0.1] — 2025-Q4

Initial public release. The Go CWE heuristic bundle covers 175 rules across
path traversal, SQL injection, command injection, XSS, weak crypto, and
similar patterns. Python has one performance rule (`SLOP101`: `re.compile`
inside a loop).
