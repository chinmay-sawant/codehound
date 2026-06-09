# P2.4 — PERF Ruleset Expansion: Detector Implementation

> **Parent:** `plans/p2.md` — P2.4
> **Status:** Ruleset catalog COMPLETED (212 rules in `ruleset/golang/golang.json`). Detector functions NOT yet implemented.
> **Estimated effort:** 6-8 weeks for all 112 new detector functions + test fixtures.

---

## Overview

The PERF rule catalog has been expanded from 100 to 212 rules via verified-source research. The 112 new rules (PERF-101 through PERF-212) are defined in `ruleset/golang/golang.json` but no detector functions, test fixtures, or registry entries exist for them.

---

## Phase 1: Pre-Implementation Audit

### 1.1 Verify ruleset completeness

- [ ] Audit `ruleset/golang/golang.json` for PERF-101 through PERF-212
  - [ ] Confirm each entry has: `id`, `name`, `description`, `original_description`, `category`, `applicable_to`, `go_relevance`, `detection_notes`
  - [ ] Confirm zero duplicates against PERF-1 through PERF-100
  - [ ] Confirm zero duplicates among PERF-101 through PERF-212
- [ ] Cross-reference against the executive summary at `plans/perf-extension-summary.md`
  - [ ] Verify all 112 rules match between summary and `golang.json`
- [ ] Flag any rules with incomplete `detection_notes` — these need research before implementation

### 1.2 Categorize new rules by detection difficulty

- [ ] Category A: Simple pattern match — single function call, known signature (~40% of rules)
  - [ ] Examples: `time.Tick` vs `time.NewTicker`, `defer resp.Body.Close()` missing, `filepath.Walk` vs `filepath.WalkDir`
  - [ ] Effort: ~30 min per rule (detector + fixture + registry entry)
- [ ] Category B: Context-aware pattern — requires AST context, scope analysis (~35% of rules)
  - [ ] Examples: `sync.Mutex` in struct vs local, `ioutil.ReadAll` ignored error, `strings.Builder` pre-allocation
  - [ ] Effort: ~2 hours per rule
- [ ] Category C: Multi-file or semantic — requires call-graph or type inference (~25% of rules)
  - [ ] Examples: `http.Client` without timeout across package boundaries, `database/sql` connection pool exhaustion patterns
  - [ ] Effort: ~4 hours per rule
- [ ] Create `plans/perf-category-breakdown.md` documenting which rules fall into each category

### 1.3 Identify domain organization

- [ ] Map each of the 112 new rules to existing domain modules OR new domain modules
- [ ] Existing PERF domains (`src/lang/go/detectors/perf/domains/`):
  - `data_access` — database/SQL patterns
  - `general_perf` — general Go performance patterns
  - `gin_framework` — Gin-specific patterns
  - `loop_allocations` — loop body allocation anti-patterns
  - `parsing_in_loops` — parsing inside loop bodies
  - `protocols` — HTTP, gRPC, etc.
  - `request_path` — request handling lifecycle
- [ ] New domain modules likely needed:
  - [ ] `concurrency` — goroutine, channel, mutex, atomic patterns (if rules added in this area)
  - [ ] `memory_gc` — GC pressure, escape analysis, allocation patterns
  - [ ] `stdlib_optimization` — stdlib function selection (e.g., `time.Tick` vs `NewTicker`)
  - [ ] `string_bytes` — string/byte slice optimization patterns
- [ ] Create a mapping table: `rule_id → domain_module → category`

---

## Phase 2: Registry & Metadata Scaffold

### 2.1 Add registry entries for PERF-101 through PERF-212

- [ ] Edit `src/lang/go/detectors/perf/registry.toml`
- [ ] For each new PERF rule, add:
  ```toml
  [[detector]]
  perf = <N>
  domain = "<domain_name>"
  function = "detect_perf_<N>"
  ```
- [ ] Ensure no duplicate `perf` values across the file
- [ ] Ensure `domain` field matches actual Rust module name
- [ ] Ensure `function` name matches the function that will be implemented

### 2.2 Verify build.rs handling

- [ ] Confirm that `build.rs` reads `perf/registry.toml` and generates:
  - [ ] `go_perf_registry.rs` — dispatch table with `detect_perf_101` through `detect_perf_212`
  - [ ] `go_perf_metadata.rs` — `META_PERF_101` through `META_PERF_212` constants with values from `golang.json`
- [ ] Test: add a single new registry entry, run `cargo build`, verify it compiles
- [ ] Test: verify generated code includes the new function pointer
- [ ] Test: verify `builtin_rule_catalogue()` includes the new rule

### 2.3 Update domain module declarations

- [ ] For each new domain module (if any), add `pub mod <domain>;` to `src/lang/go/detectors/perf/domains/mod.rs`
- [ ] For each new domain module, create the corresponding Rust file:
  - [ ] `src/lang/go/detectors/perf/domains/<domain>.rs`
  - [ ] Start with a placeholder: `use crate::...;` imports
  - [ ] Add stub functions for each rule assigned to this domain

---

## Phase 3: Implement Detector Functions (Batch by Category)

### 3.1 Category A: Simple Pattern Match Rules (Batch 1, ~40 rules)

For each rule in Category A:

- [ ] **Study the rule**: Read `detection_notes` in `golang.json`, understand the pattern
- [ ] **Write the detector function**:
  - [ ] Function signature: `pub fn detect_perf_N(facts: &GoPerfFacts, source: &str, file: &str, out: &mut Vec<Finding>)`
  - [ ] Pattern matching: use `facts.call_facts`, `facts.assignments`, `facts.source_index` (PerfSourceIndex)
  - [ ] Use `unit.line_col(byte_offset)` for line/column computation
  - [ ] Use `emit::push_finding(&META_PERF_N, file, line, col, "message", out)` for finding emission
  - [ ] Add rule-specific false-positive suppression logic
- [ ] **Add to domain module**: Wire the function in the appropriate domain `.rs` file
- [ ] **Follow existing detector patterns**: Study `detect_perf_1` through `detect_perf_100` for conventions
  - [ ] Use `facts.call_facts.iter()` for iterating call sites
  - [ ] Use `facts.source_index.contains("needle")` for substring checks
  - [ ] Use `facts.var_kinds` for type-based false positive suppression
  - [ ] Use `unit.snippet_of(byte_range)` for generating readable messages

### 3.2 Category B: Context-Aware Rules (Batch 2, ~40 rules)

For each rule in Category B:

- [ ] **Extend `GoPerfFacts` if needed** (`src/lang/go/detectors/perf/facts.rs`):
  - [ ] Add new fields to `GoPerfFacts` for additional AST queries (struct field analysis, type resolution, scope checks)
  - [ ] Add new fields to `PerfSourceIndex` for context-specific needle tracking
  - [ ] Implement extraction logic for the new fact types in `extract_perf_facts()`
- [ ] **Write the detector function**:
  - [ ] Use enriched `GoPerfFacts` for context-aware detection
  - [ ] Implement scope checks (e.g., "is this mutex a struct field or a local variable?")
  - [ ] Implement control-flow-aware logic (e.g., "is err checked before this call?")
  - [ ] Handle edge cases and false positives explicitly with early returns
- [ ] **Add integration points**: If new tree-sitter queries are needed, add them to the facts extraction phase

### 3.3 Category C: Multi-File / Semantic Rules (Batch 3, ~32 rules)

For each rule in Category C:

- [ ] **Design detection strategy**: Determine if multi-file analysis is truly needed or if a heuristic approximation suffices
- [ ] **If heuristic is possible**: Implement a single-file approximation with confidence annotation
  - [ ] Example: For "HTTP client without timeout across packages", check:
    - [ ] Is `http.Client{}` or `&http.Client{}` created without `Timeout` field?
    - [ ] Is the client stored in a package-level variable? (heuristic for "used across boundaries")
    - [ ] If yes → warn with note "timeout should be set, especially if this client is shared"
  - [ ] Tag these findings with a lower confidence and `Severity::Info` or `Severity::Low`
- [ ] **If multi-file is necessary**: Defer to taint tracking infrastructure (P2.1) and mark as dependent
  - [ ] Add a check: if taint tracking is not enabled, skip this rule (or emit a lower-confidence heuristic)
  - [ ] Add a TODO referencing the taint tracking plan

---

## Phase 4: Test Fixtures

### 4.1 Create test fixtures for each new PERF rule

- [ ] Create `tests/fixtures/go/perf/` directory if not already organized
- [ ] For each PERF-N (N in 101-212):
  - [ ] Create `vulnerable_perf_N.txt`:
    ```
    lang: go
    ---
    // Source code that SHOULD trigger PERF-N
    package main
    
    import (...)
    
    func main() {
        // Anti-pattern code
    }
    ```
  - [ ] Create `safe_perf_N.txt`:
    ```
    lang: go
    ---
    // Source code that should NOT trigger PERF-N
    package main
    
    import (...)
    
    func main() {
        // Correct pattern code
    }
    ```
- [ ] Use the existing fixture naming convention: `rules: [PERF-N]` header if targeting specific rules
- [ ] For rules that require context (Category B/C), create richer fixtures with imports, struct definitions, etc.

### 4.2 Integration test structure

- [ ] Extend `tests/go_perf_detector_integration.rs`
  - [ ] Update the fixture discovery logic to include PERF-101 through PERF-212
  - [ ] Currently discovers from `tests/fixtures/go/perf` — ensure new fixtures are discovered
- [ ] Add parameterized test: for each PERF-N (101-212):
  - [ ] Load `vulnerable_perf_N.txt`, assert PERF-N fires
  - [ ] Load `safe_perf_N.txt`, assert PERF-N does NOT fire
- [ ] If the fixture discovery is convention-based (looking for files with `perf_N` in name), follow that convention

### 4.3 Test helper patterns (reuse existing)

- [ ] Use `tests/helpers/mod.rs::assert_fixture_rules()` for per-fixture testing
- [ ] Use `tests/helpers/mod.rs::assert_fixture_materializes()` for materialization
- [ ] Follow the same pattern as existing PERF tests for consistency

---

## Phase 5: Documentation & Metadata

### 5.1 Verify rule descriptions in golang.json

- [ ] For each PERF-101 through PERF-212, verify `description` field is:
  - [ ] Clear and actionable
  - [ ] Includes the "why" (performance impact explanation)
  - [ ] Includes a "fix" suggestion or reference
- [ ] Update any placeholder or incomplete descriptions

### 5.2 Update detection_notes

- [ ] For each rule, expand `detection_notes` with:
  - [ ] Exact patterns to detect (call signatures, import paths)
  - [ ] Known false positive patterns
  - [ ] Any heuristics or approximations used
  - [ ] Dependencies on other rules or infrastructure

### 5.3 Severity assignment

- [ ] Review severity for each new PERF rule:
  - [ ] `Critical`: Will cause production outage under load (memory leak, goroutine leak, deadlock)
  - [ ] `High`: Significant performance degradation (blocking I/O in hot path, unnecessary allocations in loops)
  - [ ] `Medium`: Suboptimal pattern with measurable impact (wrong stdlib function, missing pooling)
  - [ ] `Low`: Minor optimization opportunity (micro-optimization, style preference)
  - [ ] `Info`: Educational / best practice suggestion
- [ ] Update `metadata_overrides.rs` or the `golang.json` severity field

---

## Phase 6: Performance Validation

### 6.1 Benchmark detector overhead

- [ ] Measure scan time with only PERF-1 through PERF-100 (baseline)
- [ ] Measure scan time with PERF-1 through PERF-212 (expanded)
- [ ] Target: <1.3× slowdown (112 new detectors, each called per file)
- [ ] If slowdown exceeds budget:
  - [ ] Profile with `cargo flamegraph` or `perf`
  - [ ] Optimize the most expensive new detectors
  - [ ] Add early-exit checks (e.g., "only run if file contains import X")

### 6.2 Add SourceIndex needles for new rules

- [ ] For new Category A/B rules, add substring needles to `PerfSourceIndex`
  - [ ] Each needle should be a distinctive substring of the pattern (e.g., import path, function name)
  - [ ] Skip detectors whose needles are all absent from the file (fast path)
- [ ] Update `extract_perf_facts()` in `facts.rs` to populate the new needles

### 6.3 Batch-compatible rules

- [ ] Identify rules that can share a single AST walk pass
  - [ ] Multiple rules checking for `for` loop bodies → single AST traversal
  - [ ] Multiple rules checking for `http.Handler` patterns → single traversal
- [ ] Refactor extraction to batch compatible queries

---

## Phase 7: Continuous Integration & Quality Gates

### 7.1 Test coverage

- [ ] Ensure each PERF-101 through PERF-212 has at least one vulnerable and one safe test fixture
- [ ] Run `cargo test` — all tests pass
- [ ] Check test coverage: `cargo tarpaulin` or similar (target: >90% for new detector code)

### 7.2 Lint & format

- [ ] Run `cargo clippy` — no warnings
- [ ] Run `cargo fmt` — all files formatted

### 7.3 Self-scan quality check

- [ ] Run `slopguard` on the slopguard codebase itself
- [ ] Review PERF findings for false positives
- [ ] Tweak detectors that produce false positives on the project's own code

---

## Phase 8: Tracking & Progress

### 8.1 Create progress tracker

- [ ] Create `plans/perf-implementation-progress.md`
- [ ] Table columns: `Rule ID | Category | Domain | Detector Implemented | Vulnerable Fixture | Safe Fixture | Test Passing | Notes`
- [ ] Update progress as rules are implemented
- [ ] Mark completion percentage at top of file

### 8.2 Batch milestones

- [ ] Milestone 1: First 20 Category A rules (detector + fixture + test) — target: week 1-2
- [ ] Milestone 2: Remaining 20 Category A rules — target: week 3-4
- [ ] Milestone 3: First 20 Category B rules — target: week 4-6
- [ ] Milestone 4: Remaining 20 Category B rules — target: week 6-8
- [ ] Milestone 5: Category C rules (heuristic + deferred) — target: week 8+

---

## Dependencies

- `ruleset/golang/golang.json` (PERF-101 through PERF-212 ruleset definitions, already complete)
- `src/lang/go/detectors/perf/registry.toml` (registry entries, partially complete — needs 112 new entries)
- `build.rs` (code generation from registry + ruleset, already handles PERF patterns)
- `src/lang/go/detectors/perf/facts.rs` (GoPerfFacts + PerfSourceIndex, may need extension for Category B/C)
- `src/lang/go/detectors/perf/domains/mod.rs` (domain module declarations)
- `tests/fixtures/go/perf/` (test fixture directory)
- `tests/go_perf_detector_integration.rs` (integration test)
- `tests/helpers/mod.rs` (test helpers)
