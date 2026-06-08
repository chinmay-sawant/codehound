# Plan 5: Tests & CI — Coverage Gaps & Verification

> **Priority:** Medium (regression prevention)

## Background

Several features exist in the code but have no dedicated tests. The CI bench parsing is fragile. benchmarks.md claims implementations that don't exist.

## Checklist

### Phase 1: New unit tests

- [x] **1.1** Create `tests/engine_sinks.rs`:
  - [x] Test `matches_sink()` returns true for known members
  - [x] Test `matches_sink()` returns false for non-members
  - [x] Test each phf_set! contains expected entries
  - [x] Test adding a sink doesn't break existing assertions

- [x] **1.2** Add tests to `tests/lang_go_detectors_cwe_common.rs`:
  - [x] `argument_uses_identifier("path", "path")` → `true` (exact match fast path)
  - [x] `argument_uses_identifier("filepath.Join(base, path)", "path")` → `true` (substring match)
  - [x] `argument_uses_identifier("otherVar", "path")` → `false`
  - [x] `argument_uses_identifier("user_name", "user")` → `false` (underscores don't split)
  - [x] `argument_uses_identifier("", "path")` → `false` (empty argument)
  - [x] `argument_uses_identifier("v.Name", "v")` → `true` (dot-separated)
  - [x] `argument_uses_identifier("v.Name", "Name")` → `true`

- [x] **1.3** Add tests to `tests/ast_walk.rs`:
  - [x] TreeCursor correctly visits all nodes in DFS pre-order
  - [x] TreeCursor handles empty trees
  - [x] TreeCursor handles deeply nested trees (>1000 depth)

- [x] **1.4** Add tests for SourceIndex (in existing test file or new):
  - [x] `build()` populates correct flags for known substrings
  - [x] `has()` returns true for present needles
  - [x] `has()` returns false for absent needles
  - [x] `has_any()` works correctly with multiple needles

### Phase 2: Integration tests

- [x] **2.1** Add a test fixture that exercises `argument_uses_identifier` substring matching:
  - Vulnerable: wrapped expression `os.ReadFile(filepath.Join(base, userInput))`
  - Safe: same pattern with proper confinement

- [x] **2.2** Add an integration test for the sink registry:
  - Scan a file using each sink category
  - Verify the correct rule fires for each

### Phase 3: CI bench fix

- [x] **3.1** Verify the criterion `--output-format bencher` format
- [x] **3.2** Fix the parsing in `ci.yml:103-104` to reliably extract time
- [x] **3.3** Test locally: run `make bench` and verify the CI script correctly parses the output

### Phase 4: benchmarks.md audit

- [x] **4.1** Run `cargo bench` against current code
- [x] **4.2** Update benchmarks.md with actual measured numbers
- [x] **4.3** Mark all "planned but not implemented" items clearly
- [x] **4.4** Add a "To Be Implemented" section for items still pending

### Phase 5: README update

- [x] **5.1** Add severity levels table (Info/Low/Medium/High/Critical with descriptions)
- [x] **5.2** Mention sink registry architecture
- [x] **5.3** Mention 175+ CWE catalog (auto-generated)
- [x] **5.4** Update module organization description
- [x] **5.5** Add link to Review2.md and architecture plans

## Verification

- [x] `make lint` passes
- [x] `cargo test` — all tests pass including new ones
- [x] `make bench` — CI parse script correctly extracts times
- [x] `cargo test --test engine_sinks` — new tests pass
