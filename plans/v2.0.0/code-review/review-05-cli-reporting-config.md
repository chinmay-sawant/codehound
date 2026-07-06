## Review Summary — CLI, Reporting, Config & Plans

**Verdict:** REQUEST CHANGES

**Overview:** Large, well-structured refactoring that splits monolithic modules (CLI, scan context, reporting, AST functions, language) into submodule directories. The architecture is clean and the modularization follows solid engineering principles. A few correctness and performance issues in the Python detector, SARIF output, and schema warrant fixes before merge.

### Critical Issues

- **`slopguard.schema.json:17` — TypeScript in config enum without feature gate.** The `enum` for `languages` includes `"ts"` and `"typescript"`, but `LanguageId::TypeScript` only exists behind `#[cfg(feature = "typescript")]`. If a user's config validation passes but the binary was built without the feature, `LanguageId::from_config_name` returns `None` and the language is silently skipped. At minimum the schema should note the feature flag; ideally the schema is generated or includes a `oneOf` with a `"not": {"enum": ["ts", "typescript"]}` fallback when the feature is absent.
  - **Fix:** Either (a) conditionally include `"ts"/"typescript"` in the schema at build time, or (b) add a validation error in `resolve_language_filter` when an unsupported language name is given, rather than silently dropping it.

- **`src/reporting/sarif/log.rs:55` — Every SARIF result tagged "security" unconditionally.** The line `let mut tags: Vec<String> = vec!["security".to_string()];` prepends the tag "security" to all results, including PERF-* (performance) and BP-* (bad-practice) findings. SARIF consumers that filter on this tag (e.g. GitHub Code Scanning severity overrides) will see false classifications.
  - **Fix:** Initialize `tags` empty; push `"security"` only when `category_for_rule_id` returns `"security"` (or when `f.rule_id` starts with `"CWE-"` but doesn't start with `"PERF-"` or `"BP-"`).

- **`src/lang/python/matchers.rs:5-7` — `ends_with(".compile(")` is fragile.** The heuristic matches the node's full text with `.compile(` as a suffix. Tree-sitter call nodes can span multiple lines or contain whitespace before `(`. This will produce false negatives for multi-line calls like `re.compile(\n    pattern\n)` and false positives for any function whose text happens to end with `.compile(`.
  - **Fix:** Walk the call node's children to find the function expression and match `re.compile` against its text via a named child query. At minimum, trim whitespace before the `(` check.

### Important Issues

- **`src/reporting/sarif/log.rs:68-73` — O(n²) tag dedup.** The inner loop calls `tags.contains(tag)` (O(n)) for each extra tag. With typical tag counts (<10) this is harmless, but the pattern is fragile and wastes CPU on large result sets.
  - **Fix:** Use a `HashSet` for dedup or start building `tags` from a `BTreeSet`/`HashSet` to guarantee O(1) per insert.

- **`src/reporting/sarif/time.rs:1-3` — Duplicated `iso8601_utc_now` logic.** The comment itself says "duplicated across engine modules; future cleanup would extract them into a single `engine/time.rs`". This was flagged in the plan but not resolved.
  - **Fix:** Extract `iso8601_utc_now` (and `unix_epoch_to_ymdhms`) into `src/engine/time.rs` or a shared `crate::util::time` module. Remove the copy in `sarif/time.rs` and re-import.

- **`src/reporting/sarif/entry.rs:47` — `String::from_utf8` on SARIF serialization.** `serde_json::to_writer_pretty` always produces valid UTF-8 (JSON is always UTF-8), so the `from_utf8` fallback will never trigger. The error variant `Error::Walk("SARIF JSON is not valid UTF-8: ...")` misleads readers into thinking this code path is reachable.
  - **Fix:** Use `String::from_utf8(buf).unwrap()` with a comment noting it is infallible, or use `unsafe { String::from_utf8_unchecked(buf) }`.

- **`src/reporting/sarif/log.rs:124` — `working_directory` uri is `"."` (relative).** The SARIF spec expects absolute URIs for `workingDirectory` in many CI integrations (GitHub, Azure DevOps). A relative path like `.` may cause resolution failures in downstream CI tooling.
  - **Fix:** Resolve to an absolute path via `std::env::current_dir()` or `std::path::absolute()`.

- **`src/app/config.rs:28` — `Option::is_none_or` usage.** This method was stabilized in Rust 1.82. If the project needs to support older MSRV than 1.82, this will fail to compile. The CI specifies MSRV 1.85, so this is acceptable — but it's worth noting that `is_none_or` is relatively new and may surprise readers.
  - **Fix:** Either add a comment noting the MSRV requirement, or replace with `config.map_or(true, SlopguardConfig::baseline_enabled)` for broader compatibility.

- **`src/reporting/text/style.rs:3-58` — `cfg(feature = "terminal-output")` gate for colored output.** The `#[cfg(feature = "terminal-output")]` module uses `colored::Colorize` while the fallback strips styling. This is correct. However `style.rs:61` does `pub use terminal::*;` which re-exports both modules (one gets shadowed by cfg). This works but is slightly confusing — the `pub use terminal::*;` at the bottom re-exports whichever `terminal` module was compiled.
  - **Fix:** Minor, but consider renaming the modules `impl_terminal` / `impl_noop` for clarity.

### Suggestions

- **`src/reporting/text/render.rs:56-61` — Snippet rendering always uses 4-space indent.** Hardcoded `"    "` prefix works but won't align nicely with deeply nested code. Consider reading the snippet's indentation from the source file.
- **`src/reporting/json/types.rs:101` — `format!("CWE-{}", c.id)` is called per-finding.** For large scans (10k+ findings) this adds allocation pressure. Pre-compute the `DisplayCweRef` string at `CweRef` construction time or cache it.
- **`src/lang/python/detectors/re_compile_in_loop.rs:47-48` — `walk_calls` walks the entire CST for every file.** For Python files with few functions but many calls, this is correct but wasteful. A tree-sitter `Query.captures` for `call` nodes would be more efficient. Worth profiling before optimizing.
- **`src/reporting/sarif/log.rs:44` — `security_severity` for bad_practice is hardcoded to "5.0".** This is reasonable as a default but should be documented as a decision. Consider deriving from the finding's actual severity when possible.
- **`plans/p2-implementation/01-taint-tracking.md` — Phase 1 is marked complete but Phase 1.1–1.4 have all `[ ]` unchecked.** The list is checkbox-based but all items show `[ ]` even for completed phases. Confusing for future readers. Recommend using `[x]` for checked items if the section is complete.
- **`slopguard.schema.json:45` — `exclude_tests` default is `true` but `templates/slopguard.toml` comments say it's `false`.** The template says `# exclude_tests = false` while the schema says `"default": true`. These need to match.
- **`scripts/check_no_prod_expect.sh:33,43` — Regex `\.(expect|unwrap)\(` matches within string literals and comments (though comments are filtered).** The script handles single-line comments but may still miss inline comments after code. The heuristic is effective but not airtight. Consider a comment noting this limitation.
- **`CHANGELOG.md:299-312` — Deferred items are well documented but there's no target release date or tracking issue for Phase C-F of taint tracking.** Consider linking to the plan documents.

### What's Done Well

- **Clean module hierarchy.** The refactoring from monolithic files to submodule directories (`cli/`, `reporting/`, `app/`, `core/scan/`, `ast/function/`, `core/language/`) dramatically improves navigability. Each module has a single responsibility.
- **`ScanContext` now carries time-to-live fields** (`debug_timing`, `diagnostics`, `taint_enabled`, `bad_practices_enabled`, `show_ignored`) with zero-cost no-op when disabled via `collect_stats()`. This sets a solid foundation for future observability features.
- **`DetectorKind` enum** cleanly separates heuristic bundles from fact-driven detectors, enabling the scheduler to optimize execution order in future iterations.
- **`Fingerprint` struct** and `FingerprintParseError` provide a typed foundation for stable finding identity across formats, baseline matching, and CI diffing. The `Display` and `parse` round-trip is well-implemented.
- **`sarif/schema.rs`** separates SARIF 2.1.0 DTOs from builder logic, keeping `log.rs` focused on transformation. `skip_serializing_if` annotations correctly handle optional fields.
- **`text/style.rs` cfg-gating** with `#[cfg(feature = "terminal-output")]` cleanly handles colored output without runtime branching or pulling in `colored` on all builds.
- **`check_no_prod_expect.sh`** adds a safety net against `unwrap`/`expect` in production code — a pragmatic CI guard that catches a real class of bugs.
- **`plans/p2-executive-summary.md`** and the `p2-implementation/` plan documents are thorough and well-organized. They objectively compare against alternatives (CodeQL, Semgrep, Ruff, Snyk) and justify the market niche.

### Verification Story
- Tests reviewed: Partial — Python detector has no test file in this diff. SARIF/text/json output modules lack test coverage in the reviewed files. Existing test infrastructure was not audited.
- Build verified: Not verified in this review (no `cargo check` run).
- Security checked: Yes — `check_no_prod_expect.sh` adds production unwrap/expect prevention. SARIF "security" tag misclassification flagged as a correctness issue. Python regex heuristic flagged for false-negative potential.
