# Architecture & performance notes

## Pipeline (language-agnostic)

```
CLI/config merge → Analyzer → collect_entries (walk + include/exclude filtering) → scan_entries_parallel (read + parse + detect per file) → reporting
```

Each file is read, parsed, analyzed, and dropped independently so peak memory stays bounded on large repos.

## Multi-language default

- **Cargo `default` features**: `go` + `python` (not Go-only).
- **`--lang auto`**: extension-based plugin selection; a walk over `.` parses `.go` and `.py` in one run.
- **No `--lang` required** for mixed monorepos.

## Performance choices

| Area | Before | After |
|------|--------|-------|
| Parser | New `Parser` + `set_language` per file | `ParsePool`: one parser per `LanguageId` per file (thread-local in parallel scan) |
| Detectors | Every detector × every file | `Registry.by_language`: only matching rules per file |
| Go AST | Detector-specific repeated passes | Bundled `GoCweScan` fact-build pass for Go CWE heuristics |
| CWE metadata | `cwe_slice` allocated + leaked per finding | Static `CWE_REFS_*` slices in `cwe/catalog.rs` |
| File pipeline | Parse all files into `Vec`, then analyze | Parallel read → parse → detect → drop per file (`rayon`) |
| Source load | `read` + `from_utf8().to_owned()` (double copy) | `String::from_utf8(bytes)` into `Arc<str>` |
| Walk | Single grammar | Plugin lookup by extension (O(plugins), typically 2–3), plus config-backed include/exclude path filtering |

## Config behavior

- `only` and `skip` are additive across config and CLI. The effective rule set is the union of `slopguard.toml` and CLI entries.
- `fail_on` from config applies only when the CLI did not explicitly set `--strict`, `--no-fail`, or `--warnings-as-errors`.
- `include` and `exclude` are gitignore-style path globs applied during file collection, relative to each scan root passed on the CLI.
- `.slopguardignore`, `.gitignore`, and `.ignore` remain active alongside config-backed include/exclude filtering.

## Complexity (typical repo)

- Walk: O(files)
- Parse + detect: O(files / cores) wall time with rayon; O(files) work total after walk-time filtering
- Per file: one tree-sitter parse + one Go AST walk (or one walk per language bundle)
- Detect: O(files × rules_for_that_language); not O(files × all_rules)

## Future optimizations (not needed yet)

- Incremental tree-sitter parse when caching file hashes
- Tree-sitter Query captures instead of recursive walks for hot rules
- Extension → plugin `HashMap` when language count grows

## Line budget

Keep `src/` under ~2,500 LOC; split files before 120 lines.
