# SlopGuard TODO — 2026-06-05 Session 2

## Test Migration (move `mod tests` out of src/ → tests/)

### Small (easy, no pub issues)
- [x] Move `mod tests` from `src/cwe/catalog.rs` to `tests/cwe_catalog.rs` (`tests/cwe_catalog.rs`)
- [x] Move `mod tests` from `src/rules/severity.rs` to `tests/rules_severity.rs` (`tests/rules_severity.rs`)
- [x] Move `mod tests` from `src/reporting/text.rs` to `tests/reporting_text.rs` (`tests/reporting_text_basic.rs` et al.)
- [x] Move `mod tests` from `src/fixture/format.rs` to `tests/fixture_format.rs` (`tests/fixture_format.rs`)
- [x] Move `mod tests` from `src/ast/location.rs` to `tests/ast_location.rs` (`tests/ast_location.rs`)
- [x] Move `mod tests` from `src/engine/result.rs` to `tests/engine_result.rs` (`tests/engine_result.rs`)
- [x] Move `mod tests` from `src/engine/language_filter.rs` to `tests/engine_language_filter.rs` (`tests/engine_language_filter.rs`)
- [x] Move `mod tests` from `src/export/mod.rs` to `tests/export.rs` (`tests/export.rs`)

### Medium (custom `pub` re-exports needed)
- [x] Move `mod tests` from `src/rules/finding.rs` to `tests/rules_finding.rs` (`tests/rules_finding_construction.rs`)
- [x] Move `mod tests` from `src/rules/emit.rs` to `tests/rules_emit.rs` (`tests/rules_emit.rs`)
- [x] Move `mod tests` from `src/engine/config.rs` to `tests/engine_config.rs` (`tests/engine_config_parsing.rs` et al.)
- [x] Move `mod tests` from `src/ast/walk.rs` to `tests/ast_walk.rs` (`tests/ast_walk_go.rs`, `tests/ast_walk_python.rs`)
- [x] Move `mod tests` from `src/core/unit.rs` to `tests/core_unit.rs` (`tests/core_unit.rs`)
- [x] Move `mod tests` from `src/reporting/json.rs` to `tests/reporting_json.rs` (`tests/reporting_json_envelope.rs`, `tests/reporting_json_finding.rs`)

### Big (needs pub items, depends on facts/common being pub)
- [x] Move `mod tests` from `src/reporting/sarif.rs` to `tests/reporting_sarif.rs` (`tests/reporting_sarif_snapshot.rs`, `tests/reporting_sarif_core.rs`)
- [x] Move `mod tests` from `src/lang/go/detectors/cwe/facts.rs` to `tests/lang_go_detectors_cwe_facts.rs` (`tests/lang_go_detectors_cwe_facts_builder.rs`, `tests/lang_go_detectors_cwe_facts_helpers.rs`)
- [x] Move `mod tests` from `src/lang/go/detectors/cwe/common.rs` to `tests/lang_go_detectors_cwe_common.rs` (`tests/lang_go_detectors_cwe_common_guards.rs`, `tests/lang_go_detectors_cwe_common_args.rs`)

### Cross-cutting
- [x] `Cargo.toml` dev-deps: add `tree-sitter`, `tree-sitter-go`, `tree-sitter-python` (non-optional) (`Cargo.toml` line 78–80)
- [x] Fix: `src/reporting/sarif.rs` has duplicate `write_sarif` + old `print_with` — need to consolidate (refactored to `src/reporting/sarif/` dir)
- [x] Fix: `src/reporting/sarif.rs` `write_sarif` borrow-after-move on `out` in the if/else branches (refactored to `src/reporting/sarif/log.rs`)
- [x] Fix: `Cargo.toml` cannot have `optional = true` in `[dev-dependencies]` (no `optional` in `[dev-dependencies]`)

## Deferred Architecture Items
- [ ] A2: Split `GoCweScan` into per-rule detectors (macro-based) (still a single `GoCweScan` struct, not macro-split)
- [x] A6: `build.rs` codegen for JSON rule catalogue (`build.rs` with `gen_catalogue`, `gen_cwe`, `gen_perf`)
- [x] Perf CI: add regression gate (`tests/perf_regression.rs`)

## Finalization
- [ ] `cargo test --all` passes (needs review)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean (needs review)
- [x] Update `CHANGELOG.md` (`CHANGELOG.md` exists and has entries)
- [ ] Save PR summary to `plans/v0.0.1/PR/` (directory not found)
