# Adding a language to CodeHound

## Layout

```
src/lang/<lang>/
  mod.rs            # LanguagePlugin + inventory registration (see go/register.rs)
  detectors/        # Detector impls (optional domain split like go/detectors/)
  # optional: parser helpers live in src/lang/parser.rs (shared pool)

ruleset/<lang>/     # optional ruleset data (Go: ruleset/golang/chunks/*.json)
  chunks/           # preferred: split JSON catalogues (not a single flat file)

tests/fixtures/<lang>/
  sample.txt        # mandatory text fixture (materialized under target/ at test time)
```

Reference implementation: `src/lang/go/` (CWE + PERF + BP) and `src/lang/python/`.

## Steps

1. Add `LanguageId` variant in `src/core/language/`.
2. Add Cargo feature + `tree-sitter-*` dependency in `Cargo.toml`.
3. Add feature to `default` array when the language ships to all users.
4. Implement `LanguagePlugin` under `src/lang/<lang>/` and register via `inventory` / `src/lang/register.rs`.
5. Wire detectors implementing `core::Detector` (and optional build-time registry like Go PERF/CWE TOML).
6. **Optional:** override `LanguagePlugin::extract_deps(unit, project)` for cache cascade.
   - `project` is [`ProjectContext`](../src/core/language/plugin.rs) — language-neutral, currently only `root`.
   - Derive any language-specific module/package data **inside the plugin** (Go reads `go.mod` itself).
   - Prefer the `tree_sitter_lang!` optional 10th-argument closure `|unit, project| -> Vec<String>`.
   - Return project-local paths; the engine normalizes and deduplicates for cache keys.
7. **Mandatory tests:**
   - `tests/fixtures/<lang>/` with at least one `.txt` text fixture
   - Entry in `tests/fixtures/manifest.toml` (paths must end in `.txt`)
   - `tests/<lang>_integration.rs` using `tests/helpers` (materialize → analyze)

## Shared helpers

- `ast::walk` / location helpers under `src/ast/`
- `cwe::CWE_CATALOG` / `CweRef` for rule metadata
- `engine::ParsePool` reuses one parser per language per Rayon worker
- `core::ProjectContext` for language-neutral dependency extraction

## CLI

- `--lang auto` (default): detect from extension; mixed repos scan all enabled languages
- `--lang go` / `--lang python`: force a single language

## Default build

`default = ["go", "terminal-output", "cli"]` — **Go-first**. Enable Python with
`--features python` (experimental). See [ADR 0005](./adr/0005-multi-lang-honesty.md).
