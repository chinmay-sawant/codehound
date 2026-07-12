## Review Summary — Performance & Bad Practice Detectors

**Verdict:** REQUEST CHANGES

**Overview:** Large refactoring that splits the monolithic PERF detector files into domain-aligned modules (data_access, gin_framework, general_perf, etc.) and introduces a new bad_practices detector bundle (BP-1..15). The source_index refactoring (precomputed substring flags) is a good performance win. However, there are correctness bugs in BP-5, BP-6, BP-8, stale doc comments that will confuse future readers, and the PerfSourceIndex::has() O(n) linear scan over 544 needles undermines the performance intent.

### Critical Issues

- **`src/lang/go/detectors/bad_practices/rules/sync.rs:67-83` — BP-8 flags every `defer mu.Unlock()` as a mutex copy, massive false positives.** The function `detect_bp_8_defer_unlock_on_mutex_copy` flags any line matching `defer .Unlock()` regardless of whether the mutex is a value copy. `defer mu.Unlock()` after `mu.Lock()` is the canonical Go pattern, not a bad practice. The detector cannot distinguish a value copy from a pointer receiver embed — it needs AST-level type info or at minimum a check that the mutex is declared as a value (not pointer) in a struct literal. Until then, this rule will fire on almost every correct Go codebase that uses mutexes. **Fix:** Remove the rule or gate it behind a `*sync.Mutex` absence check (only flag when mutex is embedded as `sync.Mutex` (value) in a struct literal that's constructed per handler, and `defer .Unlock()` is on the value copy — very narrow. The current heuristic is wrong for ~99% of real usage.

- **`src/lang/go/detectors/bad_practices/rules/error_handling.rs:113-121` — BP-5 `= ` substring match yields false negatives/positives.** The `handled` variable uses `trimmed.contains("= ")` which matches any line with `= ` anywhere: function params, strings, comments. A line like `// equals = true` is considered "handled". Also, `if !handled || trimmed.starts_with("defer ")` always flags defers, even correct ones like `defer func() { if err := resp.Body.Close(); err != nil { log.Error(err) } }()`. **Fix:** Use AST-based detection: look for `call_expression` with callee ending in `.Close` that is either a bare statement or defer, and whose return value is not assigned to anything non-blank. The current line-level regex is fundamentally imprecise.

### Important Issues

- **`src/lang/go/detectors/bad_practices/rules/sync.rs:18-36` — BP-6 goroutine brace tracking is fragile.** The function uses `if trimmed == "}" || trimmed == "}()" { in_goroutine = false; }` to detect end of goroutine. This breaks on nested braces inside the goroutine (e.g., `go func() { if x { wg.Add(1) } }()` would exit `in_goroutine` at the first `}` after `x {`). **Fix:** Count brace depth instead of boolean tracking, or use tree-sitter AST to find `go_statement` boundaries.

- **`src/lang/go/detectors/perf/domains/gin_framework/handler_validation.rs:31` — Doc comment says PERF-52 but function is `detect_perf_57` (PERF-52 is runtime.GC; this checks Gin middleware heavy work).** The doc comment was copied from old monolithic file and not updated during domain split. Same issue at:
  - `src/lang/go/detectors/perf/domains/gin_framework/middleware_and_routing/router_setup.rs:8` — doc says `PERF-58`, function is `detect_perf_61`
  - `src/lang/go/detectors/perf/domains/gin_framework/handler_patterns/request_io.rs:25` — doc says `PERF-57`, function is `detect_perf_58`
  - `src/lang/go/detectors/perf/domains/gin_framework/handler_patterns/goroutine_lifecycle.rs:9` — doc says `PERF-61`, function is `detect_perf_64`
  
  **Fix:** Sync doc comments with function names. The registry.toml mappings are correct; only the source doc strings are stale.

- **`src/lang/go/detectors/perf/source_index.rs:571` — `PerfSourceIndex::has` is O(n) linear scan over 544 needles on every call.** Each `has("...")` call does `NEEDLES.iter().position(|n| *n == needle)`. With ~50+ `has()` calls per file across all detectors, this is ~27k string comparisons per file. For a performance analysis tool, this is ironic. **Fix:** Build a `HashMap<&'static str, usize>` once (lazy_static or `std::sync::OnceLock`) that maps needle → index, giving O(1) lookup. Or use `phf` for compile-time perfect hashing.

- **`src/lang/go/detectors/perf/source_index.rs:571-574` — `has()` silently returns `false` for unlisted needles.** If a detector calls `has("some_new_pattern")` that isn't in `NEEDLES`, it returns `false` without any diagnostic. This means adding a new needle to a detector requires remembering to add it to `NEEDLES`, or the detector silently never fires. **Fix:** Add `debug_assert!` or a compile-time check that all needles used by detectors are in `NEEDLES`. Or better, generate `NEEDLES` from the registry to enforce coherence.

- **`src/lang/go/detectors/bad_practices/rules/panics.rs:32-38` — BP-3 `in_main` flag is never reset after exiting `func main()`.** When the tree walk encounters a `function_declaration`, it sets `*in_main = name == "main"`. After visiting children of `func main()`, the flag stays `true` for any sibling function declared after `main` in the AST. This means `panic()` in a function after `main` is incorrectly silenced. **Fix:** Save/restore `in_main` around the function body walk: `let prev = *in_main; *in_main = name == "main"; ... walk children ...; *in_main = prev;`

### Suggestions

- **`src/lang/go/detectors/perf/domains/gin_framework/common.rs:1-8` and `data_access/common.rs` — `first_pos` and `emit_at` helpers are duplicated across domain `common.rs` files.** `gin_framework/common.rs` has `first_pos`, `emit_at`, `top_commas`; `data_access/common.rs` has `call_in_loop_with`, `has_any`, `substr_has_any`. These could live in `perf/common.rs` instead of being duplicated per-domain. **Suggestion:** Move `emit_at` and `first_pos` into `perf/common.rs`.

- **`src/lang/go/detectors/perf/domains/general_perf/concurrency_and_path/goroutines.rs:85` — `let _source = unit.source.as_ref()` is dead code.** Leftover from refactoring where `is_request_path` now uses `facts.source_index`. Several other detectors also have unused `source` bindings. **Suggestion:** Remove unused `let _source` and `let _ = source` patterns.

- **`src/lang/go/detectors/perf/source_index.rs:4-544` — `NEEDLES` contains ~30-40 entries that are never referenced by any detector.** Examples: `email`, `ip`, `uuid`, `user`, `username`, `account`, `tenantId`, `orderId`, `sessionId`, `traceId`, `clientIp`, etc. These appear to be speculative "may be useful later" entries. They bloat the 544-entry index and slow down both `build()` and `has()` lookups. **Suggestion:** Remove unused needles; they can be added back when a detector actually uses them (YAGNI).

- **`src/lang/go/detectors/perf/domains/protocols/common.rs:7-10` — `index_matches_any` is a one-line delegate to `index.has_any` with no behavioral change.** It adds indirection without value. All callers could use `facts.source_index.has_any(...)` directly. **Suggestion:** Remove or inline.

- **`src/lang/go/detectors/perf/domains/general_perf/concurrency_and_path/channels_and_select.rs:15-18` — `make(chan T, ` is checked as a specific needle, but `make(chan int, `, `make(chan string, `, `make(chan struct{}, ` are duplicates of the same pattern.** If any buffered channel literal is present, the function returns early. The three specific type variants are redundant — the wildcard `make(chan T, ` alone would suffice. **Suggestion:** Keep only the general `make(chan T, ` needle (or `, ` after `make(chan`) and remove the type-specific variants.

- **`src/lang/go/detectors/bad_practices/source_index.rs` — BadPractice `SourceIndex` is built as a separate pass even when `PerfSourceIndex` is also built.** If both BP and PERF detectors run on the same file, the source string is scanned twice for substring presence. **Suggestion:** Either merge the needle sets and share one index, or make `SourceIndex` lazily constructable from a subset of the perf index.

### What's Done Well

1. **New bad-practice detector bundle (BP-1..15) fills a real gap.** Go has well-known pitfalls (discarded errors, mutex copies, panic outside main, background context in libraries) that existing Go linters handle inconsistently. The chosen rule set targets high-signal, low-noise patterns — especially BP-1, BP-9, BP-10, and BP-13.

2. **Domain-split directory structure is clean and navigable.** The old monolithic files (`gorm_queries.rs`, `allocations_and_reuse.rs`, `concurrency_and_path.rs`) were 250-400 lines each. The new structure breaks these into focused sub-modules like `buffer_pooling.rs`, `fmt_and_append.rs`, `sync_mutex.rs` — each 70-130 lines with a single responsibility. The `mod.rs` files are minimal re-exports.

3. **SourceIndex refactoring — precomputed substring flags across the entire codebase.** Replacing repeated `source.contains(...)` calls (each O(n) scan of the source) with a single `PerfSourceIndex::build()` pass is a genuine performance improvement for the common case where multiple detectors run on the same file. The guard clause pattern (`if !facts.source_index.has(...) { return; }`) is consistently applied across ~90% of detectors.

4. **Registry-driven code generation** — The split into `registry.*.toml` files per domain with `build.rs` generating the dispatch table is clean. It decouples rule metadata from implementation and makes it easy to add/remove rules without touching dispatch code. The per-domain registries are a significant improvement over the single 500-line `registry.toml`.

5. **Consistent error message style** — Every finding message follows the same pattern: describe what's happening, state the consequence, and imply the fix. No abbreviations, no jargon. Examples: "GORM query inside a loop body suggests an N+1 access pattern; use Preload or batch the fetch" — clear even to a junior Go developer.

### Verification Story

- **Tests reviewed:** yes. Three test files (`go_perf_detector_integration.rs`, `go_perf_registry_generation.rs`, `go_perf_ruleset_audit.rs`) cover fixture-based end-to-end testing, registry-toml alignment, and ruleset JSON coverage. The fixture-based approach (`discover_go_perf_cases()` + `assert_fixture_rules`) is thorough — every PERF rule has a vulnerable and safe fixture. The registry test ensures generated code matches TOML. No dedicated tests for the new bad_practice detectors (BP-1..15) were found — these should be added before merging.

- **Build verified:** not run (review-only shard). The refactoring is mechanically large (104 files, 8.9k insertions) and the registry generation depends on build.rs; a full build should be performed.

- **Security checked:** yes. No findings introduce code execution, injection, or privilege escalation vectors. The detectors are pure static analysis — they read source files and produce findings. BP-4 (recover without logging) is a reliability/observability concern, not a security boundary violation.
