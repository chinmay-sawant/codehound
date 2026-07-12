# D5 — V0.0.1 Legacy Deferred

> **Parent:** `plans/v0.0.1/`
> **Status:** 24 items deferred to v0.0.3, 2 resolved since initial audit
> **Estimated effort:** TBD

---

## Overview

Deferred items from v0.0.1 legacy plan files that were not yet implemented at time of audit.

---

## Phase 1: Session TODOs

### 1.1 TODO-2026-06-05-session2.md

- [ ] Split GoCweScan into per-rule detectors (macro-based) — still a single GoCweScan struct
- [ ] `cargo test --all` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] Save PR summary to `plans/v0.0.1/PR/` — directory not found

## Phase 2: CWE Fixtures

### 2.1 generate-cwe-fixtures.md

- [ ] `cargo test` passes for `go_integration` and `fixture_manifest_integration`

### 2.2 pure-go-fixtures.md

- [ ] Pre-existing off-by-one in `tests/fixtures/go/` ↔ manifest resolved
- [ ] `cargo test --test go_integration` passes
- [ ] `cargo test --test fixture_manifest_integration` passes

## Phase 3: SARIF & Perf Heuristics

### 3.1 perf-heuristics-and-sarif.md

- [x] Include concise message text explaining both hot-path issue and preferred reuse pattern
- [x] Add stable fingerprints
- [ ] `make fmt`
- [ ] `make lint`
- [ ] Add rule metadata beyond `id`, `name`, and `shortDescription` in SARIF
- [ ] Include `helpUri` or `properties` in SARIF when rule registry has enough information
- [ ] Add focused SARIF regression test for mixed `CWE-*` and `PERF-*` findings

## Phase 4: PR Reviews

### 4.1 pr-architecture-performance-2026-06-02.md

- [ ] `cargo fmt --check`
- [ ] No unrelated changes in diff

### 4.2 pr-refactor-go-cwe-and-add-perf-plan.md

- [ ] No unrelated changes in diff
- [ ] No secrets or generated artifacts committed

### 4.3 pr-performance-parallel-scan.md

- [ ] `cargo run -- target/codehound-fixtures` — manual verification run, not automated
- [ ] Scan large repo and compare wall time vs previous sequential build — manual benchmark

## Phase 5: Architecture & Performance

### 5.1 architecture-performance-review-2026-06-05.md

- [ ] Callee-indexed rule scheduling to skip rules when sinks are absent
- [ ] Incremental tree-sitter parse / file-hash cache
- [ ] Further shrink `general_security` hot paths beyond `SourceIndex` (tree-sitter queries)

---

## Count

| Status | Count |
|--------|-------|
| Total | 24 |
| `[x]` (implemented) | 2 |
| `[ ]` (not implemented) | 22 |
| `[~]` (deferred) | 0 |
