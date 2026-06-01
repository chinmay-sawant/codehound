# Adding a language to SlopGuard

## Layout

```
src/lang/<lang>/
  mod.rs          # LanguagePlugin impl
  parser.rs       # configure + parse_with (reused parser pool)
  loop_kinds.rs   # loop node kind strings
  matchers.rs     # AST predicates
  detectors/      # one file per rule

tests/fixtures/<lang>/
  sample.txt      # mandatory text fixture (materialized to .go/.py/.rs at test time)
```

## Steps

1. Add `LanguageId` variant in `src/core/language.rs`.
2. Add Cargo feature + `tree-sitter-*` dependency in `Cargo.toml`.
3. Add feature to `default` array when the language ships to all users.
4. Implement `LanguagePlugin` in `src/lang/<lang>/mod.rs`.
5. Register in `src/lang/mod.rs` under `#[cfg(feature = "...")]`.
6. Add detectors implementing `core::Detector`.
7. **Mandatory tests:**
   - `tests/fixtures/<lang>/` with at least one `.txt` text fixture
   - Entry in `tests/fixtures/manifest.toml` (paths must end in `.txt`)
   - `tests/<lang>_integration.rs` using `tests/helpers` (materialize → analyze)

## Shared helpers

- `ast::walk_calls`, `ast::walk_assignments`, `ast::nearest_loop`
- `cwe::catalog::CWE_REFS_*` static slices (or compose from `CWE_CATALOG` consts) for rule metadata
- `engine::ParsePool` reuses one parser per language per scan

## CLI

- `--lang auto` (default): detect from extension; mixed repos scan all enabled languages
- `--lang go` / `--lang python`: force a single language

## Default build

`default = ["go", "python"]` — mixed Go + Python repositories work without flags.
