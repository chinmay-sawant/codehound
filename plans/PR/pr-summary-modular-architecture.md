# PR Summary: CodeHound modular architecture & multi-language testing

## Overview

This PR turns CodeHound from a Go-only bootstrap into a **modular, multi-language static analyzer** with trait-based plugins, performance-oriented scanning, and a **`.txt` text fixture** workflow for tests (no committed `.go`/`.py`/`.rs` under `tests/fixtures/`).

---

## Phase 1: Fix build & modular core

### Problem

- `src/lib.rs` contained README markdown instead of Rust → 290 compile errors.
- Detectors were coupled to Go `SourceFile`; duplicated AST walks; broken `--skip`; unused `SeverityArgs`.

### Changes

- Restored proper `lib.rs` module tree.
- Added `src/core/` (`LanguageId`, `ParsedUnit`, `Detector`, `ScanContext`, `FailPolicy`).
- Added `src/ast/` (shared `walk_calls`, `nearest_loop`, `snippet_of`, `line_col`).
- Added `src/engine/` (orchestration).
- Moved Go detectors to `src/lang/go/`.
- Moved `cwe_slice` → `src/cwe/helpers.rs`.
- Fixed `--skip` / `--only` via `ScanContext::allows`.
- Wired `--strict` / `--no-fail` exit policy.

---

## Phase 2: Language plugins & registry

### Changes

- `LanguagePlugin` trait: parse, detectors, loop node kinds.
- `Registry` with plugin lookup by extension.
- CLI `--lang auto|go|python` (default: **auto**).
- Cargo features: `go`, `python`, `all-langs`.

---

## Phase 3: Config & SARIF

### Changes

- Optional `codehound.toml` + `engine/config.rs`.
- SARIF reporter in `reporting/sarif.rs` (replaces runtime bail).

---

## Phase 4: Second language (Python)

### Changes

- `src/lang/python/` with `SLOP101` (`re.compile` in loop).
- `tree-sitter-python` behind `python` feature.

---

## Multi-language by default (user request)

### Before

`default = ["go"]` — Python required `--features python`.

### After

```toml
default = ["go", "python"]
go = ["dep:tree-sitter-go"]
python = ["dep:tree-sitter-python"]
```

Mixed repos work with `codehound .` and `--lang auto` (extension-based plugin selection).

---

## Performance improvements

| Optimization | Detail |
|--------------|--------|
| **ParsePool** | One tree-sitter `Parser` per language per scan |
| **Registry.by_language** | Only run detectors for each file’s language |
| **parse_with** | Hot path avoids `Parser::new` per file |

Docs: `documents/architecture-performance.md`.

---

## Test fixtures: `.txt` text format (corrected)

### User requirement

Fixtures must be **plain text (`.txt`)**, not real source extensions in the repo. At test/runtime, convert to Go/Python/Rust, then run detection.

### Format (`tests/fixtures/<lang>/sample.txt`)

```text
lang: go
file: sample.go
---
package sample
...
```

### Pipeline (`codehound::fixture`)

1. `parse_fixture()` — read header + body after `---`
2. `materialize_fixture()` — write `target/codehound-fixtures/<lang>/<file>`
3. `Analyzer::analyze_paths()` on generated sources

### Layout

```
tests/fixtures/
  manifest.toml
  README.md
  go/sample.txt
  python/sample.txt
  rust/sample.txt          # materialized; Rust plugin TBD
tests/
  helpers/mod.rs
  go_integration.rs
  python_integration.rs
  mixed_integration.rs
  fixture_manifest_integration.rs
```

**Removed:** all `.slop` files (replaced with `.txt`); committed `.go`/`.py` under fixtures.

**Gitignored:** `target/codehound-fixtures/`

---

## Test results

```
cargo test  → 8 passed
```

| Test | Validates |
|------|-----------|
| `go_integration` | `go/sample.txt` → materialize → SLOP001 |
| `python_integration` | `python/sample.txt` → SLOP101 |
| `mixed_integration` | All `.txt` → Go + Python in one scan |
| `fixture_manifest_integration` | Manifest paths end in `.txt`, rules fire |
| Unit tests | Fixture parser, map_alloc detector |

---

## Source layout (final)

```
src/
  core/          # traits & ScanContext
  ast/           # shared tree-sitter helpers
  engine/        # Analyzer, Registry, ParsePool, walk, config
  fixture/       # .txt parse + materialize
  lang/go/       # 4 detectors (SLOP001–004)
  lang/python/   # SLOP101
  rules/ cwe/ reporting/ cli/
tests/fixtures/{go,python,rust}/*.txt
```

~1,700 LOC in `src/` (under 2,500 budget).

---

## Breaking / migration notes

| Item | Note |
|------|------|
| Library API | `analyzer::*` → `engine::*`; re-exports on crate root |
| Fixtures | Only `.txt` under `tests/fixtures/`; no `.go`/`.py` committed |
| Default build | Includes Go + Python |
| CLI | `--lang auto` scans all enabled languages by extension |

---

## Suggested PR title

**feat: modular multi-language analyzer, .txt fixtures, and mixed-repo defaults**

---

## Test plan (for reviewers)

- [x] `cargo test` — verified at PR time (merged)
- [x] No `*.go` / `*.py` / `*.slop` under `tests/fixtures/` — verified: only `.txt` files present
- [x] Only `*.txt` fixtures present — verified
- [x] After tests: `target/codehound-fixtures/go/sample.go` exists — materialized at test time
- [x] `cargo run -- target/codehound-fixtures` → Go + Python findings — pipeline works
- [x] `cargo run -- tests/fixtures` with materialize step (or scan materialized dir)

---

## Follow-ups (out of scope)

- TypeScript `LanguagePlugin`
- Rust detector plugin (fixture stub exists)
- Parallel file parsing (rayon)
- CI script enforcing line-count / fixture manifest
