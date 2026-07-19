# refactor(plugin): remove Go-shaped inputs from language-plugin dep seam

## Summary

Replace the Go-specific `module_prefix: Option<&str>` argument on
`LanguagePlugin::extract_deps` with a language-neutral `ProjectContext`
that carries only the resolved project root. The Go plugin now reads
`go.mod` itself; the engine keeps cache-key path normalization and no
longer discovers Go module prefixes during scan orchestration.

## Motivation / context

Architecture review §2.3 (issue #59, epic #56): the public plugin seam
and `Analyzer` scan path forced Go module semantics into every language.
A language with different project/module rules could not implement
dependency extraction without engine edits for `go_module_prefix`.

Plan: `plans/v0.0.5/rust-architecture-review.md` §2.3

## Changes

### Core API

- Add `core::ProjectContext<'a> { root: &'a Path }` with `ProjectContext::new`.
- `LanguagePlugin::extract_deps(&self, unit, project: &ProjectContext<'_>) -> Vec<String>`
- Re-export `ProjectContext` from `core` / `core::language`.

### Macro + plugins

- `tree_sitter_lang!` optional closure is now `|unit, project| -> Vec<String>`.
- **Go:** derives `module_prefix` via `go_module_prefix(project.root)` inside the plugin.
- **Python:** uses `project.root` only (unchanged import resolution).

### Engine

- `extract_dependencies(unit, project_root)` — no `module_prefix` arg.
- Cache-key strip/normalize/sort/dedup remains in `dependencies/entry.rs`.
- `scan_entries_parallel` / `ScanRequest` no longer carry `module_prefix`.
- Analyzer always passes discovered `project_root` for dep extraction
  (removed Go-gated `dependency_root` selection via `module_prefix.is_some()`).
- Go BP prewarm left unchanged (lifecycle / #60 / #57 out of scope).

### Tests + docs

- Non-Go `PathOnlyPlugin` unit test proves dep extraction needs only `ProjectContext::root`.
- Cache helpers updated to the new `extract_dependencies` signature.
- `documents/adding-a-language.md` documents the neutral seam.
- Architecture performance table row updated.

## Code snippets

### Before

```rust
fn extract_deps(
    &self,
    unit: &ParsedUnit,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<String>;
// Analyzer: let module_prefix = go_module_prefix(&project_root);
```

### After

```rust
pub struct ProjectContext<'a> {
    pub root: &'a Path,
}

fn extract_deps(
    &self,
    unit: &ParsedUnit,
    project: &ProjectContext<'_>,
) -> Vec<String>;

// Go plugin:
let module_prefix = go_module_prefix(project.root).unwrap_or_default();
```

## Out of scope

- BP scan-scoped caches (#57)
- Full detector session / project lifecycle redesign (#60)
- Hardening Go BP prewarm beyond existing behavior

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test engine_cache_scan`
- [x] `cargo test --locked --test lang_plugin_inventory`
- [x] `cargo test --locked non_go_plugin_extract_deps`
- [x] `cargo test --locked --test engine_cache_invalidation`
- [x] `make test` (412 passed; one baseline timing test flaked once under load, passed on re-run)

## Related issues

- Closes #59
- Relates to #56
