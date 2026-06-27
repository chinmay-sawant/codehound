## Review Summary — Tests & Build Infrastructure

**Verdict:** REQUEST CHANGES

**Overview:** Large, well-structured diff that modularizes the build system, splits monolithic test files into focused per-area tests, and adds export infrastructure. Two blocking issues: a filesystem race in the incremental benchmark that makes results unreliable, and untested export module. Several smaller issues flagged below.

### Critical Issues

- `benches/incremental_partial_scan.rs:40-56` — The benchmark mutates source files **inside** `b.iter()` closure (writes `"\n// slopguard-bench-touch"`, runs scan, then restores originals). Criterion invokes the closure multiple times, potentially concurrently; the filesystem state is shared mutable state across iterations. This produces non-deterministic measurements and can silently measure I/O from competing criteria iterations. **Fix:** Move file mutation and restoration into `b.iter_to_custom` setup/teardown, or use a fresh copy of the fixture tree per iteration outside the measured section.

- `src/export/` (entire module, 5 files) — The export infrastructure (`export_findings`, `finding_context_lines`, `format_finding_block`, `write_chunk_files_streaming`) has **zero test coverage** in the test suite. Any regression in context extraction, chunk boundary arithmetic, or file I/O will go undetected. **Fix:** Add at minimum: (1) unit test for `finding_context_lines` with snippet, function-range, and fallback paths; (2) test for `format_finding_block` output shape; (3) integration test for `export_findings` writing files to a temp directory and verifying their contents.

### Important Issues

- `benches/incremental_partial_scan.rs:66` — `content_hash("hello")` call inside `bench_cache_hit_in_process`'s `b.iter()` closure has its result discarded (`let _ = content_hash("hello")`). This is a dead call that wastes CPU cycles in the measured region, adding noise to the "warm in-memory" benchmark. **Fix:** Remove the dead `content_hash` call.

- `benches/incremental_partial_scan.rs:54` — `let _ = to_change.len();` at the end of the `b.iter()` closure is a no-op dead statement. **Fix:** Remove.

- `build.rs:45-102` — `read_registry_entries` and `read_perf_registry_entries` are nearly identical (only the TOML struct type and error message prefix differ). This is a DRY violation: a directory-scanning bug fix must be applied to both copies. **Fix:** Extract a shared generic `read_registry_entries<T: DeserializeOwned>(path, label)` function in `build/types.rs`.

- `tests/helpers/reporting.rs:31-35` — `sample_with_cwe` uses `Box::leak(Box::new(...))` to obtain a `&'static [CweRef]`. While correct for shared test helpers, this leaks memory in every test binary that links it. In integration tests this is benign (process exits after tests), but it's a pattern that may accidentally be copied into production code. **Fix:** Use `Cow::Owned(vec![])` and have `FindingInputs` accept `Cow<[CweRef]>` if it already doesn't, or document the pattern as test-only with a `#[cfg(test)]` guard.

- `build/parse.rs:13-18` — `parse_cwe_number` and `parse_perf_number` use `unwrap_or(id)`, meaning un-prefixed strings pass through to `parse::<u32>()`. If a malformed string like `"FOO-123"` is passed, `unwrap_or` returns `"FOO-123"` and parsing fails silently (returns `None`). This is correct for the current callers, but is a footgun if these functions are reused in contexts where validation is expected. **Fix:** Use `id.strip_prefix("CWE-")?.parse().ok()` with `?` to make the prefix requirement explicit and fail fast for unknown prefixes.

- `rustfmt.toml` — sets `edition = "2024"` which was experimental/nightly at the time of this diff. Unless the project explicitly pins a Rust nightly toolchain, this will cause a build failure on stable Rust. **Fix:** Pin to `edition = "2021"` unless the MSRV explicitly targets nightly.

### Suggestions

- `build/gen_cwe.rs:44-54` and `build/gen_perf.rs:24-36` — The metadata generation functions pass `escape_rust_string(&rule.name)` three times (name, description CWE ref name) but it's actually called for the name, description, and name-again positional slots. Consider naming the format parameters so readers don't have to count positionals.

- `tests/rules_finding_construction.rs:58-62` — `Box::leak(Box::new(...))` is used to get a `&'static` slice for test data. This is fine for tests but the `std::sync::OnceLock<Vec<CweRef>>` or similar would be cleaner and wouldn't leak. Outside critical, just a style note.

- `benches/common/mod.rs:7-14` — `unique_cache_dir` uses `as_nanos()` for uniqueness. Collision risk is negligible but `tempfile::TempDir` would eliminate it and ensure cleanup. Since `tempfile` is not a dependency, this is fine as-is — just a note.

- `tests/helpers/baseline.rs`, `go_cwe_cases.rs`, `go_perf_cases.rs`, `manifest.rs`, `inline_ignore.rs` — These files are listed in the helpers directory but I did not see their diffs in scope. If they are new, review similarly for correctness and coverage.

- `Cargo.toml` — The `unexpected_cfgs` lint now includes `"cli"` and `"typescript"`. Good, matches the new features. The new clippy lints (`all = "deny"`) are aggressive — be prepared for CI failures on trivial pedantic warnings. Consider starting with `restriction` group warnings instead of deny.

- `src/export/finding_block.rs:72-74` — `finding_context_lines` is called for each finding in a loop. Each call may re-read the same source file from disk (via `file_cache`) per finding. Consider batching context retrieval by file to reduce syscall overhead, though the `file_cache` HashMap already mitigates repeated reads from the same file.

### What's Done Well

- **Build.rs modularization is excellent.** Splitting the monolithic 400-line `build.rs` into `build/types.rs`, `parse.rs`, `escape.rs`, `gen_catalogue.rs`, `gen_cwe.rs`, `gen_perf.rs` with a clean dependency graph is exactly the right refactor. Each generator is independently testable and readable.

- **Test decomposition is well-judged.** Replacing `rules_finding.rs` (214-line monolith) and `reporting_sarif.rs` (125-line monolith) with focused files (`_construction`, `_serialization`, `_structured`, `_fingerprint`, `_core`, `_region`, `_snapshot`, `_structured`) makes test failures trivially diagnosable from the test name. The pattern of 1-2 asserts per test case is maintained consistently.

- **Snapshot testing with insta.** The three snapshot files (JSON envelope, SARIF, text summary) are redacted correctly for non-deterministic fields (timestamps, versions). This gives automated regression detection for the output formats without brittle string matching.

- **Compile-time empty-registry guard.** `const _: () = assert!(!GO_RULES.is_empty());` in `gen_cwe.rs:75` and `gen_perf.rs:57` prevents deploying with an empty detector registry — a clever compile-time safety net.

- **Backward-compatibility tests.** `tests/reporting_json_finding.rs:84-113` (`legacy_json_consumers_ignore_structured_fields`) explicitly verifies that old consumers that deserialize a slim `LegacyFindingJson` struct still work when the JSON includes new structured fields. Formalizes backward compat instead of relying on serde's default ignore behavior.

- **Evidence round-trip coverage.** `tests/rules_evidence.rs` covers all four `DetectorEvidence` variants (DangerousCall, TaintFlow, MissingConfig, ControlFlowIssue) with JSON round-trip assertions — important for a serialization boundary.

### Verification Story

- Tests reviewed: yes — all new/modified test files read. Coverage is thorough for finding construction, serialization, fingerprinting, evidence, and all three report formats (JSON, SARIF, text). Edge cases covered: empty-CWE-slice-to-None, unicode paths in fingerprints, Windows path normalization, legacy consumer compat. **Missing:** export module has zero tests.
- Build verified: yes — build.rs refactoring is clean. Registry now supports directory-based TOML loading. Cargo.toml correctly marks clap as optional behind `cli` feature. One concern: `rustfmt.toml` edition 2024 may not compile on stable Rust.
- Security checked: yes — no unsafe code, no password/token exposure, no command injection in build scripts. `sha2` dependency is standard and appropriate for content hashing. `escape_rust_string` handles all required Rust string escape sequences.
