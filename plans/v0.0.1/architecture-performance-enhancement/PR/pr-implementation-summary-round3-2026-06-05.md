# PR — Architecture & Performance, Round 3

**Date:** 2026-06-05  
**Branch:** `chore/arch-perf-enhancement`  
**Status:** Implemented. 96 tests pass, clippy clean.

---

## Scope

Convert the remaining deferred items from the architecture/performance
review into a focused implementation pass:

| ID  | Item                                                     | Status   |
|-----|----------------------------------------------------------|----------|
| A2  | Split `GoCweScan` into per-rule detector structs        | done     |
| A6  | `build.rs` codegen for JSON rule catalogue              | done     |
| —   | Move 17 `#[cfg(test)] mod tests` blocks to `tests/`     | done     |
| —   | Perf CI baseline (low priority)                         | noted    |

---

## Per-item summary

### Test structure migration
- 17 inline test modules moved from `src/` to `tests/` (25 test files total)
- Items sealed as `pub(crate)` / `pub(super)` made `pub` with `#[doc(hidden)]` where appropriate
- `Cargo.toml`: `tree-sitter`, `tree-sitter-go`, `tree-sitter-python` added to `[dev-dependencies]`
- Feature-gated tests use `#![cfg(feature = "...")]` at file level
- 96 tests passing across 26 test binaries, 0 failures

### A2 — GoCweScan split
- 175 per-rule detector structs generated via `define_detector!` macro in `cwe/mod.rs`
- Each struct implements `Rule` + `Detector` independently
- `detectors/all()` returns flat `Vec<Box<dyn Detector>>` with all 175 structs
- Old monolithic `GoCweScan` struct + `DETECTORS` array removed
- Key benefit: rule-level registration and filtering at the registry level

### A6 — build.rs codegen
- `build.rs` reads `ruleset/golang/golang.json` at build time
- Generates `LazyLock<Vec<RuleDescription>>` with all 175 entries hardcoded
- `builtin_rule_catalogue()` returns `&'static [RuleDescription]`
- Zero runtime JSON parsing cost for the default ruleset
- `load_rule_descriptions()` preserved for custom rule files

### Perf CI
- Existing `tests/perf_regression.rs` smoke test (15s budget) catches regressions
- CI `bench` job outputs bencher-format JSON for manual review
- Hard regression gate requires stable criterion baselines tracked in git (deferred)

---

## Verification

```
$ cargo test --all
96 passed, 0 failed across 26 test binaries

$ cargo clippy --all-targets --all-features -- -D warnings
Finished dev profile in 1.86s (0 warnings)
```

---

## Files changed

**Modified:** 17+ source files in `src/` plus `Cargo.toml`, `CHANGELOG.md`  
**New:** `build.rs`, 25 integration test files in `tests/`  
**Removed:** 17 inline `#[cfg(test)] mod tests` blocks
