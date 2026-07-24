## Context

`--export-context` / `--export-chunks` wrote finding and chunk files whose `Context:` section was always:

```text
<context unavailable>
```

even when the scan produced real findings (e.g. `make run SCAN_PATH=…/gopdfsuit RUN_ARGS="--export-context --export-chunks"` → 915 context files, all empty of source).

Root cause: findings store **project-relative** paths (e.g. `internal/handlers/handlers.go`). A v0.0.7 audit change forced `retain_sources: false` for all CLI scans and relied on lazy disk re-reads from the process cwd. When the scan root is outside cwd (`make run` default), those relative paths do not resolve and export falls back to `<context unavailable>`.

Docs and `ScanContext` still state that export should opt into `source_cache` retention.

## Scope (in)

1. Restore CLI wiring: `retain_sources = export_context || export_chunks`.
2. Keep default (non-export) scans with `retain_sources: false` (no monorepo RAM tax).
3. Add regression tests for relative-path export with retained sources, and for empty-cache relative-path failure.
4. Unit-test that export flags enable source retention.

## Out of scope

- Redesigning export to stream/lazy-read only finding files with multi-root path resolution
- Changing finding path identity (project-relative remains)
- Memory budgets / streaming export for very large monorepos (follow-up)

## Success criteria

- [ ] With `--export-context` / `--export-chunks`, context and chunk files include real source snippets when scanning an absolute path outside cwd
- [ ] Without export flags, `retain_sources` stays false
- [ ] Focused tests pass; no `<context unavailable>` on the gopdfsuit `make run` export path for normal findings

## Plan

- Fix: `src/app/run.rs` (`scan_context_params_for_run`)
- Tests: `tests/engine_source_cache_export_go.rs`, unit test in `src/app/run.rs`
- Product contract: `documents/architecture-performance.md` (source cache only when `retain_sources`; CLI export flags)

## References

- Introduced by: `f56ff6b` (v0.0.7 safety audit — lazy export path)
- Related docs: `documents/architecture-performance.md`, `src/core/scan/context.rs`
