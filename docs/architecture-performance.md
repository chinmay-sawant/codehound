# Architecture & performance notes

## Pipeline (language-agnostic)

```
CLI → Analyzer → collect_units (walk + parse pool) → analyze_units (per-lang detectors) → reporting
```

## Multi-language default

- **Cargo `default` features**: `go` + `python` (not Go-only).
- **`--lang auto`**: extension-based plugin selection; a walk over `.` parses `.go` and `.py` in one run.
- **No `--lang` required** for mixed monorepos.

## Performance choices

| Area | Before | After |
|------|--------|-------|
| Parser | New `Parser` + `set_language` per file | `ParsePool`: one parser per `LanguageId` per scan |
| Detectors | Every detector × every file | `Registry.by_language`: only matching rules per file |
| Walk | Single grammar | Plugin lookup by extension (O(plugins), typically 2–3) |
| Allocations | `plugin.detectors()` at registry build | Once per `Analyzer::build()` |

## Complexity (typical repo)

- Walk: O(files)
- Parse: O(files) × tree-sitter parse cost; parsers reused
- Detect: O(files × rules_for_that_language); not O(files × all_rules)

## Future optimizations (not needed yet)

- Parallel file parse (rayon) across files
- Incremental tree-sitter parse when caching file hashes
- Query-based tree-sitter captures instead of full `walk_calls` for hot rules

## Line budget

Keep `src/` under ~2,500 LOC; split files before 120 lines.
