# Architecture & performance notes

## Pipeline (language-agnostic)

```
CLI/config merge → Analyzer → collect_entries (walk + include/exclude filtering) → scan_entries_parallel (read → cache lookup | parse + detect per file) → cache flush + prune → reporting
```

Each file is read, parsed, analyzed, and dropped independently so peak memory stays bounded on large repos.

## Incremental cache (P2.3)

- **Directory**: `.slopguard-cache/` at the project root (auto-discovered near `.git` or `go.mod`).
- **Manifest**: `manifest.json` tracks per-file content hash, mtime, and dependency list; kept in memory during the scan.
- **Per-file entries**: `files/<sha256>.json` stores serialized findings, content hash, and dependency list.
- **Cache hit flow**: File is read for hash computation → hash matches manifest → findings served from cache → inline-ignore directives re-applied from the (already in-memory) source → `ctx.allows()` filters rules skipped via `--skip` / `--only`.
- **Transitive invalidation**: When a file's content hash changes, every cache entry that lists it as a dependency is invalidated. Dependency extraction walks Go `import` statements and Python `import` statements to build the dependency graph. Only project-local imports (matching the `go.mod` module prefix) are tracked; stdlib and third-party imports are excluded.
- **Pruning**: After each scan, entries for files no longer on disk are removed. `--prune-cache` prunes without scanning. `--rebuild-cache` purges the entire cache directory.
- **CLI flags**: `--no-cache`, `--cache-dir <DIR>`, `--rebuild-cache`, `--prune-cache`.
- **Configuration**: `[slopguard.cache]` block with `enabled`, `path`, and `max_size_mb` (default 500 MiB).
- **Fair warning in `--diagnostics`**: The document includes total cache size via `CacheStore::total_size()`.

## Multi-language default

- **Cargo `default` features**: `go` + `python` (not Go-only).
- **`--lang auto`**: extension-based plugin selection; a walk over `.` parses `.go` and `.py` in one run.
- **No `--lang` required** for mixed monorepos.

## Performance choices

| Area | Approach |
|------|----------|
| Parser | `ParsePool`: one parser per `LanguageId` per Rayon worker |
| Detectors | `Registry.by_language`: only matching rules per file |
| Go AST | One `build_go_unit_facts` pass + `SourceIndex` substring flags per file |
| Go rules | Typed `registry.toml` drives `build.rs` (no source scraping) |
| CWE metadata | Static `CWE_REFS_*` slices in `cwe/catalog.rs` |
| File pipeline | Parallel read → parse → detect → drop per file (`rayon`). Cache hits skip parse+detect entirely. |
| Source load | `String::from_utf8(bytes)` into `Arc<str>` |
| Source cache | Successful UTF-8 files are retained in `AnalysisResult.source_cache` as `Arc<str>` so export and downstream consumers avoid second disk reads |
| Export | Stream context files and chunk files (no upfront `Vec` of all blocks) |
| Timing / stats | Collection enabled by `--debug-timing` or `--diagnostics`; zero-cost `TimingCollector` no-ops when disabled; `ScanStats` merged from per-file `TimingSpan` values |
| Diagnostics | Optional `--diagnostics <FILE>` writes a JSON document with phase timing, detector timing, scan params, and file-level stats |

## Codebase conventions (enforced)

| Rule | Limit / policy |
|------|----------------|
| `src/**/*.rs` module file | **≤ 400 lines** (split before exceeding) |
| Go CWE detector | One **domain module** under `domains/` per ruleset category |
| New Go CWE rule | Add `[[detector]]` to `registry.toml` + implement in the matching `domains/*.rs` |
| Binary orchestration | `src/app.rs` only — `main.rs` stays tracing + `app::run` |
| Rule registry | `src/lang/go/detectors/cwe/registry.toml` is the source of truth |

Run `wc -l src/lang/go/detectors/cwe/domains/*.rs` in CI or locally to catch module growth.

## Config behavior

- `only` and `skip` are additive across config and CLI.
- `fail_on` from config applies only when the CLI did not explicitly set `--strict`, `--no-fail`, or `--warnings-as-errors`.
- `include` and `exclude` are gitignore-style path globs applied during file collection.
- `.slopguardignore`, `.gitignore`, and `.ignore` remain active alongside config-backed include/exclude filtering.
- `--debug-timing` and `--diagnostics` are CLI-only flags (no config-file equivalent); they enable per-detector timing and phase-level instrumentation.

## Complexity (typical repo)

- Walk: O(files)
- Parse + detect: O(files / cores) wall time with rayon
- Per Go file: one tree-sitter parse + one fused AST walk + one `SourceIndex` build
- Detect: O(enabled_rules × facts); `--only` skips disabled rule bodies early
- Source cache memory: O(total UTF-8 bytes scanned successfully). The cache holds one shared `Arc<str>` per successful file; a 10 MiB file therefore keeps about 10 MiB of source text alive until the `AnalysisResult` is dropped. Files that cannot be read or decoded as UTF-8 are reported as `ScanError` and omitted from the cache. Use `AnalysisResult::source_cache_bytes()` to report the retained source-text byte count for a scan.

## Benchmarks & regression tests

- `cargo bench --bench scan_throughput` — full scan, collect-only, and `--only` subset
- `cargo test materialized_fixture_scan` — wall-clock smoke tests with tight ceilings (see `tests/perf_regression.rs`)

## Future optimizations

- Size-based LRU pruning when cache exceeds `max_size_mb` (config field wired; eviction logic TBD)
- Tree-sitter Query captures for hot rules
- Callee-indexed rule scheduling to skip rules when sinks are absent
