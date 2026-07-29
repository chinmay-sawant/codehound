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

## Honesty bar

Do **not** claim parity with Go until production packs, fixtures, and maturity
tags exist. Default build is Go-first; Python is experimental. No runtime plugin
loading — [ADR 0005](./adr/0005-multi-lang-honesty.md).

## Steps

1. Add `LanguageId` variant in `src/core/language/`.
2. Add Cargo feature + `tree-sitter-*` dependency in `Cargo.toml`.
3. Add feature to `default` array **only** when the language ships to all users.
4. Implement `LanguagePlugin` under `src/lang/<lang>/` and register via
   `inventory` + feature-gated `register.rs` / `LanguagePluginRegistrar`.
5. Wire detectors implementing `core::Detector` (optional build-time registry
   like Go PERF/CWE multi-file TOML + `build.rs`).
6. Implement plugin surface as needed (see checklist below).
7. **Mandatory tests:**
   - `tests/fixtures/<lang>/` with at least one `.txt` text fixture
   - Entry in `tests/fixtures/manifest.toml` (paths must end in `.txt`;
     fixture `lang` only accepts `go` / `python` today)
   - `tests/<lang>_integration.rs` using `tests/helpers` (materialize → analyze)
8. Config `languages = ["python"]` **fails** without the Cargo feature — document
   that in user-facing notes when you ship.

## `LanguagePlugin` checklist

Reference: Go in `src/lang/go/`, trait in `src/core/language/plugin.rs` /
`src/lang/plugin.rs`.

| Hook | Purpose |
|------|---------|
| language id / extensions | File routing |
| parse / analyze wiring | Detectors for the language |
| `extract_deps` | Project-local deps for cache cascade (paths relative to **dependency base root**; normalize via `normalize_project_path`) |
| `prepare_project` | Optional prewarm (typed facts, BP project snapshot) |
| `function_node_kinds` / `loop_node_kinds` | Shared walk helpers |
| Detector lifecycle | `begin_scan` / `run` / `accumulate_state` / `finalize` / `end_scan` as needed |
| Macro args | `tree_sitter_lang!` optional closure(s) for deps / prepare |

Go derives module prefix **inside** the plugin from `go.mod` — do not push
language-specific roots into the engine.

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
