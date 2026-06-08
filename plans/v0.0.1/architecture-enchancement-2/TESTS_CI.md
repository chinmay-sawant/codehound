# Plan 5: Tests & CI — Coverage Gaps & Verification

> **Priority:** Medium (regression prevention)

## Background

Several features exist in the code but have no dedicated tests. The CI bench parsing is fragile. benchmarks.md claims implementations that don't exist.

## Checklist

### Phase 1: New unit tests

- [ ] **1.1** Create `tests/engine_sinks.rs`:
  - [ ] Test `matches_sink()` returns true for known members
  - [ ] Test `matches_sink()` returns false for non-members
  - [ ] Test each phf_set! contains expected entries
  - [ ] Test adding a sink doesn't break existing assertions

- [ ] **1.2** Add tests to `tests/lang_go_detectors_cwe_common.rs`:
  - [ ] `argument_uses_identifier("path", "path")` → `true` (exact match fast path)
  - [ ] `argument_uses_identifier("filepath.Join(base, path)", "path")` → `true` (substring match)
  - [ ] `argument_uses_identifier("otherVar", "path")` → `false`
  - [ ] `argument_uses_identifier("user_name", "user")` → `false` (underscores don't split)
  - [ ] `argument_uses_identifier("", "path")` → `false` (empty argument)
  - [ ] `argument_uses_identifier("v.Name", "v")` → `true` (dot-separated)
  - [ ] `argument_uses_identifier("v.Name", "Name")` → `true`

- [ ] **1.3** Add tests to `tests/ast_walk.rs`:
  - [ ] TreeCursor correctly visits all nodes in DFS pre-order
  - [ ] TreeCursor handles empty trees
  - [ ] TreeCursor handles deeply nested trees (>1000 depth)

- [ ] **1.4** Add tests for SourceIndex (in existing test file or new):
  - [ ] `build()` populates correct flags for known substrings
  - [ ] `has()` returns true for present needles
  - [ ] `has()` returns false for absent needles
  - [ ] `has_any()` works correctly with multiple needles

### Phase 2: Integration tests

- [ ] **2.1** Add a test fixture that exercises `argument_uses_identifier` substring matching:
  - Vulnerable: wrapped expression `os.ReadFile(filepath.Join(base, userInput))`
  - Safe: same pattern with proper confinement

- [ ] **2.2** Add an integration test for the sink registry:
  - Scan a file using each sink category
  - Verify the correct rule fires for each

### Phase 3: CI bench fix

- [ ] **3.1** Verify the criterion `--output-format bencher` format
- [ ] **3.2** Fix the parsing in `ci.yml:103-104` to reliably extract time
- [ ] **3.3** Test locally: run `make bench` and verify the CI script correctly parses the output

### Phase 4: benchmarks.md audit

- [ ] **4.1** Run `cargo bench` against current code
- [ ] **4.2** Update benchmarks.md with actual measured numbers
- [ ] **4.3** Mark all "planned but not implemented" items clearly
- [ ] **4.4** Add a "To Be Implemented" section for items still pending

### Phase 5: README update

- [ ] **5.1** Add severity levels table (Info/Low/Medium/High/Critical with descriptions)
- [ ] **5.2** Mention sink registry architecture
- [ ] **5.3** Mention 175+ CWE catalog (auto-generated)
- [ ] **5.4** Update module organization description
- [ ] **5.5** Add link to Review2.md and architecture plans

## Verification

- [ ] `make lint` passes
- [ ] `cargo test` — all tests pass including new ones
- [ ] `make bench` — CI parse script correctly extracts times
- [ ] `cargo test --test engine_sinks` — new tests pass
