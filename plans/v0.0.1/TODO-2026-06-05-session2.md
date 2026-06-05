# SlopGuard TODO — 2026-06-05 Session 2

## Test Migration (move `mod tests` out of src/ → tests/)

### Small (easy, no pub issues)
- [ ] Move `mod tests` from `src/cwe/catalog.rs` to `tests/cwe_catalog.rs`
- [ ] Move `mod tests` from `src/rules/severity.rs` to `tests/rules_severity.rs`
- [ ] Move `mod tests` from `src/reporting/text.rs` to `tests/reporting_text.rs`
- [ ] Move `mod tests` from `src/fixture/format.rs` to `tests/fixture_format.rs`
- [ ] Move `mod tests` from `src/ast/location.rs` to `tests/ast_location.rs`
- [ ] Move `mod tests` from `src/engine/result.rs` to `tests/engine_result.rs`
- [ ] Move `mod tests` from `src/engine/language_filter.rs` to `tests/engine_language_filter.rs`
- [ ] Move `mod tests` from `src/export/mod.rs` to `tests/export.rs`

### Medium (custom `pub` re-exports needed)
- [ ] Move `mod tests` from `src/rules/finding.rs` to `tests/rules_finding.rs` (all fields already pub)
- [ ] Move `mod tests` from `src/rules/emit.rs` to `tests/rules_emit.rs`
- [ ] Move `mod tests` from `src/engine/config.rs` to `tests/engine_config.rs` (need `fail_on_to_policy` pub)
- [ ] Move `mod tests` from `src/ast/walk.rs` to `tests/ast_walk.rs`
- [ ] Move `mod tests` from `src/core/unit.rs` to `tests/core_unit.rs`
- [ ] Move `mod tests` from `src/reporting/json.rs` to `tests/reporting_json.rs`

### Big (needs pub items, depends on facts/common being pub)
- [ ] Move `mod tests` from `src/reporting/sarif.rs` to `tests/reporting_sarif.rs`
- [ ] Move `mod tests` from `src/lang/go/detectors/cwe/facts.rs` to `tests/lang_go_detectors_cwe_facts.rs`
- [ ] Move `mod tests` from `src/lang/go/detectors/cwe/common.rs` to `tests/lang_go_detectors_cwe_common.rs`

### Cross-cutting
- [ ] `Cargo.toml` dev-deps: add `tree-sitter`, `tree-sitter-go`, `tree-sitter-python` (non-optional)
- [ ] Fix: `src/reporting/sarif.rs` has duplicate `write_sarif` + old `print_with` — need to consolidate
- [ ] Fix: `src/reporting/sarif.rs` `write_sarif` borrow-after-move on `out` in the if/else branches
- [ ] Fix: `Cargo.toml` cannot have `optional = true` in `[dev-dependencies]`

## Deferred Architecture Items
- [ ] A2: Split `GoCweScan` into per-rule detectors (macro-based)
- [ ] A6: `build.rs` codegen for JSON rule catalogue
- [ ] Perf CI: add regression gate (low priority)

## Finalization
- [ ] `cargo test --all` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] Update `CHANGELOG.md`
- [ ] Save PR summary to `plans/v0.0.1/PR/`
