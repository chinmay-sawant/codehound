# P2.4 — PERF Ruleset Expansion: Detector Implementation

> **Parent:** `plans/p2.md` — P2.4
> **Status:** Ruleset catalog COMPLETED (112 rules PERF-101..212 in `golang.json`). **60 of 112 rules shipped** across 6 batches. 52 rules pending. Category B (context-aware) and Category C (semantic/multi-file) **not started**. 4 stub domain modules exist but are empty. 2 rules dropped (PERF-136, PERF-208).
> **Estimated effort:** 4-6 weeks for remaining 52 rules + hygiene work.
> **Pending work breakdown:** `plans/v2.0.0/pending-work/02-perf-detectors-remaining.md`
> **Batch plans:** `plans/perf-batch-{4,5,6}.md`, `plans/perf-category-breakdown.md`

---

## Overview

The PERF rule catalog has been expanded from 100 to 212 rules via verified-source research. The 112 new rules (PERF-101 through PERF-212) are defined in `ruleset/golang/golang.json`. The first batch of 11 Category-A detectors has been implemented in `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs`, registered in `registry.toml`, and covered by inline tests in `tests/go_perf_101_127.rs`.

---

## Phase 1: Pre-Implementation Audit

### 1.1 Verify ruleset completeness

- [ ] Audit `ruleset/golang/golang.json` for PERF-101 through PERF-212
  - [x] Confirm each entry has: `id`, `name`, `description`, `original_description`, `category`, `applicable_to`, `go_relevance`, `detection_notes` (validated by build)
  - [x] Confirm zero duplicates against PERF-1 through PERF-100 (validated by build)
  - [x] Confirm zero duplicates among PERF-101 through PERF-212 (validated by build)
- [x] Cross-reference against the executive summary at `plans/perf-extension-summary.md`
  - [x] Verify all 112 rules match between summary and `golang.json`
- [ ] Flag any rules with incomplete `detection_notes` — these need research before implementation (deferred for remaining 101 rules)

### 1.2 Categorize new rules by detection difficulty

- [x] Category A: Simple pattern match — first batch (PERF-103, 107, 115-118, 120, 122, 124, 126-127) shipped in `stdlib_misuse.rs`
- [ ] Category A remaining rules — **deferred**
- [ ] Category B: Context-aware pattern — **deferred**
- [ ] Category C: Multi-file or semantic — **deferred**
- [ ] Create `plans/perf-category-breakdown.md` documenting which rules fall into each category — **deferred**

### 1.3 Identify domain organization

- [x] First batch mapped to `general_perf` (`stdlib_misuse.rs`)
- [ ] Map remaining rules to domain modules — **deferred**
- [ ] Create `concurrency` / `memory_gc` / `stdlib_optimization` / `string_bytes` domain modules if needed — **deferred**

---

## Phase 2: Registry & Metadata Scaffold

### 2.1 Add registry entries for PERF-101 through PERF-212

- [x] Edit `src/lang/go/detectors/perf/registry.toml` — first batch (PERF-103, 107, 115-118, 120, 122, 124, 126-127) registered
- [ ] Register remaining PERF-101..212 entries — **deferred**
- [x] Ensure no duplicate `perf` values across the file (validated by build for first batch)
- [x] Ensure `domain` field matches actual Rust module name (first batch: `general_perf`)
- [x] Ensure `function` name matches the function that will be implemented (first batch)

### 2.2 Verify build.rs handling

- [x] Confirm that `build.rs` reads `perf/registry.toml` and generates:
  - [x] `go_perf_registry.rs` — dispatch table with first batch function pointers
  - [x] `go_perf_metadata.rs` — `META_PERF_103`..`META_PERF_127` constants with values from `golang.json`
- [x] Test: add a single new registry entry, run `cargo build`, verify it compiles (validated by first batch)
- [x] Test: verify generated code includes the new function pointer (validated by first batch)
- [x] Test: verify `builtin_rule_catalogue()` includes the new rule (validated by first batch)
- [ ] Re-verify for remaining 101 entries — **deferred**

### 2.3 Update domain module declarations

- [ ] For each new domain module (if any), add `pub mod <domain>;` to `src/lang/go/detectors/perf/domains/mod.rs`
- [ ] For each new domain module, create the corresponding Rust file:
  - [ ] `src/lang/go/detectors/perf/domains/<domain>.rs`
  - [ ] Start with a placeholder: `use crate::...;` imports
  - [ ] Add stub functions for each rule assigned to this domain

---

## Phase 3: Implement Detector Functions (Batch by Category)

### 3.1 Category A: Simple Pattern Match Rules (Batch 1, ~40 rules)

First batch shipped: PERF-103, 107, 115, 116, 117, 118, 120, 122, 124, 126, 127.

- [x] **Study the rule**: Read `detection_notes` in `golang.json`, understand the pattern
- [x] **Write the detector function** for first batch in `stdlib_misuse.rs`:
  - [x] Function signature: `pub fn detect_perf_N(facts: &GoPerfFacts, source: &str, file: &str, out: &mut Vec<Finding>)`
  - [x] Pattern matching: use `facts.call_facts`, `facts.assignments`, `facts.source_index` (PerfSourceIndex)
  - [x] Use `unit.line_col(byte_offset)` for line/column computation
  - [x] Use `emit::push_finding(&META_PERF_N, file, line, col, "message", out)` for finding emission
  - [x] Add rule-specific false-positive suppression logic
- [x] **Add to domain module**: Wired in `general_perf/stdlib_misuse.rs`
- [x] **Follow existing detector patterns** for first batch
- [ ] Remaining Category A rules — **deferred**

### 3.2 Category B: Context-Aware Rules (Batch 2, ~40 rules)

- [ ] Not started — **deferred**

### 3.3 Category C: Multi-File / Semantic Rules (Batch 3, ~32 rules)

- [ ] Not started — **deferred** (some rules may depend on P2.1 taint tracking)

---

## Phase 4: Test Fixtures

### 4.1 Create test fixtures for each new PERF rule

- [x] Create `tests/fixtures/go/perf/` directory exists and is organized
- [x] Inline tests for first batch in `tests/go_perf_101_127.rs`
- [ ] Create `.txt` fixtures for first batch (vulnerable + safe) — **deferred**
- [ ] Create `.txt` fixtures for remaining PERF-101..212 rules — **deferred**

### 4.2 Integration test structure

- [x] Extend `tests/go_perf_detector_integration.rs` to allow gaps in fixture IDs
- [ ] Add parameterized tests for remaining PERF-101..212 fixtures — **deferred**
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

- [x] First batch (PERF-103, 107, 115-118, 120, 122, 124, 126-127) verified by build/metadata generation
- [ ] Remaining PERF-101..212 descriptions — **deferred**

### 5.2 Update detection_notes

- [x] First batch detection notes reflected in detector implementation
- [ ] Remaining rules — **deferred**

### 5.3 Severity assignment

- [x] Severity for first batch derived from `golang.json`
- [ ] Remaining rules — **deferred**

---

## Phase 6: Performance Validation

### 6.1 Benchmark detector overhead

- [ ] Not started — **deferred** until more detectors land

### 6.2 Add SourceIndex needles for new rules

- [x] First batch uses `PerfSourceIndex` substring checks where applicable
- [ ] Remaining Category A/B rules — **deferred**

### 6.3 Batch-compatible rules

- [ ] Not started — **deferred**

---

## Phase 7: Continuous Integration & Quality Gates

### 7.1 Test coverage

- [x] First batch covered by inline tests in `tests/go_perf_101_127.rs`
- [x] Run `cargo test` — all tests pass
- [ ] Remaining fixtures and coverage — **deferred**

### 7.2 Lint & format

- [x] `cargo clippy` — no warnings
- [x] `cargo fmt` — all files formatted

### 7.3 Self-scan quality check

- [ ] Not run for first batch — **deferred**

---

## Phase 8: Tracking & Progress

### 8.1 Create progress tracker

- [ ] `plans/perf-implementation-progress.md` — **deferred**

### 8.2 Batch milestones

- [x] Milestone 1: First 11 Category A rules (PERF-103, 107, 115-118, 120, 122, 124, 126-127) — detector + inline tests + registry
- [ ] Milestone 2: Remaining Category A rules — **deferred**
- [ ] Milestone 3: First 20 Category B rules — **deferred**
- [ ] Milestone 4: Remaining 20 Category B rules — **deferred**
- [ ] Milestone 5: Category C rules (heuristic + deferred) — **deferred**

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
