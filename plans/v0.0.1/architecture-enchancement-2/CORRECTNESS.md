# Plan 2: Correctness — Severity, Bugs & Edge Cases

> **Priority:** High (user-visible correctness)

## Background

Several correctness issues were identified that affect user output or miss findings:

## Checklist

### Phase 1: Severity — 4→5 levels

- [x] **1.1** Rename `Severity::Warning` → `Severity::Medium` in `src/rules/severity.rs`
- [x] **1.2** Add `Severity::Low` between Info and Medium
- [x] **1.3** Update ordering: `Info < Low < Medium < High < Critical`
- [x] **1.4** Update `is_failure()` — Low should NOT fail (only Medium/High/Critical)
- [x] **1.5** Update `as_str()` — `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`
- [x] **1.6** Update SARIF severity mapping (`sarif.rs:185-195`):
  - Info → `"note"`, `"0.0"`
  - Low → `"warning"`, `"2.0"`
  - Medium → `"warning"`, `"5.0"`
  - High → `"error"`, `"7.5"`
  - Critical → `"error"`, `"9.5"`
- [x] **1.7** Update text reporter color coding (`text.rs:70-78`)
- [x] **1.8** Update `FailPolicy::WarningsAsErrors` → `FailPolicy::MediumAsErrors`
- [x] **1.9** Update `engine/config.rs:fail_on_to_policy` — `"medium"` as the canonical fail-on value
- [x] **1.10** Update test files referencing `Severity::Warning` and `FailPolicy::WarningsAsErrors`
- [x] **1.11** Update `codehound.toml` config comments
- [x] **1.12** Update `src/app.rs:231` template comment

### Phase 2: Fix text reporter top-rules sort bug

- [x] **2.1** In `src/reporting/text.rs:99-104`, replace `.rev()` on BTreeMap with a proper sort by count:
  ```rust
  let mut top_rules: Vec<_> = by_rule.iter().collect();
  top_rules.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
  let top: Vec<String> = top_rules.iter().take(5).map(...).collect();
  ```
- [x] **2.2** Verify: rule with most findings appears first in "top rules" output

### Phase 3: Fix NO_COLOR spec compliance

- [x] **3.1** In `src/cli/mod.rs:69-77`, replace `BoolishValueParser` with `action = ArgAction::SetTrue` for NO_COLOR
- [x] **3.2** This ensures `NO_COLOR=0` correctly DISABLES color (spec says any non-empty value disables)

### Phase 4: Fix SARIF empty-fix edge case

- [x] **4.1** In `src/rules/emit.rs:48`, change `with_fix(meta.fix.unwrap_or(""))` to only call `with_fix` when `meta.fix.is_some()`
- [x] **4.2** This prevents `fix: Some("")` from appearing in output

### Phase 5: Fix export function naming

- [x] **5.1** In `src/export/mod.rs:239`, rename parameter `keep_if` → `should_remove` (or invert predicate)
- [x] **5.2** Document the semantics clearly

### Phase 6: Audit argument_uses_identifier usage

- [x] **6.1** In `cwe/domains/injection.rs:154` (CWE-91), replace bare `.contains()` with `argument_uses_identifier` for correctness
- [x] **6.2** Verify no other bare `.contains()` on arguments-vs-identifiers exist that should use the helper

## Verification

- [x] `make lint` passes
- [x] `cargo test` — all tests pass with updated severity variant names
- [x] Manual check: `--format text` output shows top rules sorted by frequency
- [x] `NO_COLOR=0 cargo run` properly disables color
