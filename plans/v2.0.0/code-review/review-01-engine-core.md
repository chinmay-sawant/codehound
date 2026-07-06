## Review Summary — Engine & Core

**Verdict:** REQUEST CHANGES

**Overview:** Major architectural rework that successfully modularizes the engine, introduces incremental analysis caching, and adds dependency-tracking with cascade invalidation. The code quality is generally high, but a memory leak in the cache deserialization path and a sequential I/O bottleneck before the parallel scan are blocking issues. Several smaller correctness and maintainability concerns are present.

---

### Critical Issues

- **`src/rules/finding_wire.rs:62-68`, `src/rules/finding_wire.rs:84-85` — `Box::leak` memory leak on every cache read.**  
  `OwnedCweRef::into_static` and `FindingWire::into_finding` use `Box::leak` to convert heap-allocated strings into `&'static str` so deserialized findings fit the `Finding` struct's `&'static str` fields. The doc comment claims the leak is bounded to unique CWE IDs, but this is wrong: **`rule_id`** and **`rule_title`** (also leaked on lines 6984-6985) are per-finding, not per-unique-value. Every cache hit reads N findings → N leaks of `rule_id` + `rule_title` that never get reclaimed.  
  **Fix:** Redesign `Finding` to use `Box<str>` or `Arc<str>` for `rule_id` and `rule_title` instead of `&'static str`, or use a string interner. For CWE refs, the same applies — `CweRef` should hold `Box<str>` or an interned ID. This is a correctness / resource-exhaustion bug.

---

### Important Issues

- **`src/engine/walk/parallel.rs:5782-5824` — Sequential preflight file read defeats Rayon parallelism.**  
  `preflight_cache_hits` reads **every** file from disk sequentially on the main thread to compute `content_hash` before dispatching any work to Rayon. For a project with 10,000 files this is a mandatory sequential I/O pass that delays the parallel parse phase. The old code (deleted `walk.rs`) read files inside the Rayon workers, keeping I/O parallel.  
  **Fix:** Move the cache-lookup hash computation into the parallel dispatch (`dispatch_parallel_scan`) and handle cache hits in the merge phase. The preflight should only check `is_cache_hit` cheaply without reading file content, if possible, or read content in parallel workers.

- **`src/engine/cache/store_lifecycle.rs:2318-2322` — `invalidate_file` removes from manifest but leaves orphaned on-disk files.**  
  `invalidate_file` only removes the manifest entry, not the `<cache_key>.json` file on disk. The only cleanup path is `clean_orphans()`, which is called exclusively from the `--prune-cache` CLI command (`app/run.rs:468`), not in the normal scan flow. Orphaned cache files accumulate indefinitely.  
  **Fix:** Either (a) `invalidate_file` should delete the on-disk entry too (mirroring `remove`), or (b) `analyze_paths` in `src/engine/analyzer/scan.rs` should call `cache.clean_orphans()` during flush alongside `cache.prune()`.

- **`src/engine/cache/hash.rs`, `src/engine/baseline/io.rs`, `src/engine/diagnostics/clock.rs` — Triplicated ISO-8601 date conversion.**  
  Howard Hinnant's `civil_from_days` algorithm is copy-pasted across three modules with identical implementations. The `diagnostics/clock.rs` comment even admits "duplicated across engine modules; future cleanup would extract them".  
  **Fix:** Extract into a single `src/engine/time.rs` module and use it everywhere. This is a straightforward DRY refactor.

- **`src/error.rs:57-60` — `GrammarError` enum is dead code.**  
  `GrammarError` is defined with a `From` impl into `Error`, but `LanguagePlugin::configure_parser` returns `Result<(), Error>` directly (not `GrammarError`), and no code constructs `GrammarError`.  
  **Fix:** Remove `GrammarError` and its `From` impl, or use it in `configure_parser` and the cache grammar error path.

---

### Suggestions

- **`src/rules/finding_wire.rs:5650` — Dead field on `ScanOutcome::Cached`.**  
  The `language` field in `ScanOutcome::Cached` is tagged `#[expect(dead_code)]` and used nowhere. Remove it to simplify the enum.

- **`src/engine/walk/parallel.rs:5968, 5809` — `content_hash` computed twice.**  
  `preflight_cache_hits` computes `content_hash(&source)` (line 5809) for every file, then `write_cache_on_miss` recomputes it (line 5968). Thread the hash through instead.

- **`src/core/scan/context.rs` — Public fields break encapsulation.**  
  `ScanContext` has all fields `pub`. Accessing them through methods (already partially done with `allows()`, `collect_stats()`) would reduce the risk of internal changes leaking. Consider making fields non-`pub` and exposing accessors.

- **`src/engine/analyzer/scan.rs:1522-1536` — Cascade invalidation logs at `info` level per file.**  
  Each invalidated dependent produces a `tracing::info!` line. On a large change (e.g. renaming a widely imported module), this floods logs. Move to `debug`.

- **`src/engine/cache/store_flush.rs:2194-2205` — `Drop::flush` cannot propagate errors.**  
  If `flush` fails during drop (e.g. disk full), the manifest is lost but the in-memory state was already mutated. Entries written since the last successful flush become orphans. Consider at least logging the set of dirty keys for forensic debugging.

- **`src/engine/dependencies/python_imports.rs:3734-3738` — `_source_dir` parameter unused in `resolve_module`.**  
  The `_source_dir` parameter in `resolve_module` is unused (prefixed with `_`). Remove it from the signature for this function if it's never needed.

---

### What's Done Well

- **Cache architecture is well-separated** with clean lifecycle, open, flush, and eviction modules. The manifest + files/ split keeps lookups cheap and writes atomic.
- **Dependency extraction for Go and Python** is correctly scoped to project-local imports, with sensible heuristics for go.mod-less projects and relative Python imports.
- **`Error` unification across the crate** (`src/error.rs`) with `thiserror` is a significant improvement over the old ad-hoc `anyhow` usage. The `#[must_use]` annotations are thorough.
- **Parallel scan with cache preflight** correctly handles `catch_unwind` for worker panics, report them as `ScanError::Engine` without crashing the process.
- **Type-state builder pattern** (`AnalyzerBuilder<UnsetFilter>` → `AnalyzerBuilder<HasFilter>`) enforces a required `language_filter` or `with_default_filter` call before `build()`, catching misconfiguration at compile time.
- **Inline suppression directives** (`// slopguard-ignore:`) are handled for both fresh scans and cache-hit replay, with sensible `show_ignored` fallback.

---

### Verification Story

- **Tests reviewed:** Yes — `tests/engine_cache_store.rs`, `tests/engine_cache_scan.rs`, `tests/engine_baseline_store.rs`, `tests/engine_file_ignore.rs`, `tests/engine_config_parsing.rs`, `tests/engine_config_merge.rs`, `tests/engine_language_filter.rs`, `tests/engine_observability_timing.rs`, `tests/rules_emit.rs`, `tests/rules_evidence.rs`, `tests/rules_finding_serialization.rs`, `tests/rules_severity.rs`. Good coverage of cache round-trips, baseline suppression, config parsing, ignore directive mechanics, and finding serialization. No test exercises cascade invalidation end-to-end (creating a Go file with a cross-package import, editing the imported file, and verifying the dependent is rescanned). No test for `clean_orphans`. No test for cache eviction (size limit).
- **Build verified:** No. Compilation check recommended after the `Box::leak` fix.
- **Security checked:** Yes — the `Box::leak` finding is the main security concern (potential OOM under sustained use). No injection vectors identified in the reviewed shard. File path normalization (`replace('\\', '/')`) is consistently applied across fingerprinting and cache key derivation, mitigating Windows path shenanigans.
- **Crate-wide `#![deny(clippy::unwrap_used)]`** is a good safety net. It's correctly `#[allow]`ed in test modules.
