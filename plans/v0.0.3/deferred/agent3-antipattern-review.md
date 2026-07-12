# D3 — Anti-Pattern & Review Deferred

> **Parent:** `plans/v0.0.2/antipattern-remediation/`, `plans/v0.0.2/code-review/`, `plans/v0.0.2/ponytail/`
> **Status:** 22 items deferred to v0.0.3, 5 resolved since initial audit
> **Estimated effort:** TBD

---

## Overview

Deferred anti-pattern remediation, code review, and audit items from Agent 3 review of 8 plan files under `plans/v0.0.2/`.

---

## Phase 1: Runtime Safety

### 1.1 Production `.expect()` elimination

- [ ] Document invariant expects in SARIF log, rule tables, walker (3+ prod `.expect` remain in `cwe/mod.rs`, `perf/mod.rs`, `walker_core.rs`) — `m15-anti-pattern.md`
- [ ] Document invariant expects in parser/registry loading — `m15-anti-pattern.md`
- [ ] Production `.expect()` reduced to 0 — `rust-best-practices.md`
- [ ] Replace or document 3 production `.expect(` — restore `check_no_prod_expect.sh` green — `rust-remediation-phase-3.md`

---

## Phase 2: Documentation & Hygiene

### 2.1 `#![warn(missing_docs)]` on `lib.rs`

- [ ] Enable `#![warn(missing_docs)]` on `src/lib.rs` — `rust-best-practices.md`, `rust-remediation-phase-2.md`
- [ ] `#![deny(missing_docs)]` ratchet on one module — `rust-remediation-phase-2.md`

### 2.2 Runnable doc-test

- [ ] Convert `#![no_run]` to runnable doc-test for `lib.rs` quick-start — `rust-best-practices.md`, `rust-remediation-phase-2.md`

### 2.3 Heuristic rule documentation

- [ ] Document heuristic-only rules in registry TOML comment — `rust-remediation-phase-2.md`

---

## Phase 3: Testing

### 3.1 Multi-assertion test splitting

- [ ] Split multi-assertion integration tests — `rust-best-practices.md`
- [ ] Split multi-assertion envelope / SARIF tests — `rust-best-practices.md`
- [ ] Split multi-assert envelope tests — `rust-remediation-phase-2.md`
- [ ] Split SARIF log tests — `rust-remediation-phase-2.md`

### 3.2 Testing hygiene

- [ ] Adopt `pretty_assertions` (dep present, 0 usages) — `rust-best-practices.md`, `rust-remediation-phase-2.md`
- [ ] Configure `cargo insta test` CI step — `rust-remediation-phase-2.md`
- [ ] Naming convention audit — `rust-remediation-phase-2.md`

---

## Phase 4: API Surface

### 4.1 Module visibility & exports

- [ ] Shrink `engine/mod.rs` `pub use` surface (13+ groups remain) — `rust-patterns.md`
- [ ] Deprecate direct `engine::*` re-exports — `rust-remediation-phase-2.md`
- [x] Update `src/main.rs` to use `codehound::cli` via feature gate — `rust-remediation-phase-2.md`

---

## Phase 5: Code Quality

### 5.1 Code formatting & size

- [ ] `cargo fmt --check` (still failing) — `rust-remediation-phase-3.md`
- [ ] `cargo fmt` + commit formatting — `rust-remediation-phase-3.md`
- [ ] `scan_entry` orchestrator — 76 lines (target <60) — `rust-remediation-phase-3.md`
- [ ] Trim `scan_entry` orchestrator to <60 lines — `rust-remediation-phase-3.md`

---

## Resolved Since Audit

### Builder / `#[must_use]` gaps

- [x] Type-state `AnalyzerBuilder` replaced by ponytail with simple builder — `rust-best-practices.md`
- [x] `Registry::default` / builder methods — `#[must_use]` added — `rust-remediation-phase-2.md`
- [x] Type-state `AnalyzerBuilder<HasRegistry, HasFilter>` — `rust-remediation-phase-2.md`

### Performance

- [x] Rebaseline or optimize index build for `perf_regression` smoke budget — `rust-remediation-phase-3.md`

---

## Count

| Status | Count |
|--------|-------|
| Not Implemented `[ ]` | 22 |
| Resolved `[x]` | 5 |
| **Total** | **27** |
