# Deferred Items — Agent 3 Anti-Pattern Review

> **Source:** Audit of 8 plan files under `plans/v2.0.0/`
> **Date:** 2026-07-05
> **Total deferred:** 22 items (after deduplication)

---

## Production `.expect()` not eliminated

| Source file | Item |
|---|---|
| `m15-anti-pattern.md` | Document invariant `expect`s (SARIF log, rule tables, walker) — 3+ prod `.expect` remain in `cwe/mod.rs`, `perf/mod.rs`, `walker_core.rs` |
| `m15-anti-pattern.md` | Document invariant `expect`s in parser/registry loading |
| `rust-best-practices.md` | Production `.expect()` reduced to 0 |
| `rust-remediation-phase-3.md` | Replace or document 3 production `.expect(` (restore `check_no_prod_expect.sh` green) |

---

## `#![warn(missing_docs)]` not enabled on `lib.rs`

| Source file | Item |
|---|---|
| `rust-best-practices.md` | `#![warn(missing_docs)]` enabled on `lib.rs` (x2) |
| `rust-remediation-phase-2.md` | Enable `#![warn(missing_docs)]` on `src/lib.rs` |
| `rust-remediation-phase-2.md` | `#![deny(missing_docs)]` ratchet on one module |

---

## Runnable doc-test not converted from `#no_run`

| Source file | Item |
|---|---|
| `rust-best-practices.md` | Runnable doc-test for `lib.rs` quick-start (x2) |
| `rust-remediation-phase-2.md` | Runnable doc-test for `lib.rs` quick-start |

---

## Multi-assertion tests not split

| Source file | Item |
|---|---|
| `rust-best-practices.md` | Split multi-assertion integration tests (x2) |
| `rust-best-practices.md` | Split multi-assertion envelope / SARIF tests |
| `rust-remediation-phase-2.md` | Split multi-assert envelope tests |
| `rust-remediation-phase-2.md` | Split SARIF log tests |

---

## Testing hygiene

| Source file | Item |
|---|---|
| `rust-best-practices.md` | `pretty_assertions` adoption (dep present, 0 usages) |
| `rust-remediation-phase-2.md` | `pretty_assertions` still unused |
| `rust-remediation-phase-2.md` | `cargo insta test` CI step not configured |
| `rust-remediation-phase-2.md` | Naming convention audit |

---

## Module visibility & exports

| Source file | Item |
|---|---|
| `rust-patterns.md` | Shrink `engine/mod.rs` `pub use` surface (13+ groups remain) |
| `rust-remediation-phase-2.md` | Deprecate direct `engine::*` re-exports |
| `rust-remediation-phase-2.md` | Update `src/main.rs` to use `slopguard::cli` via feature gate (now implemented) |

---

## Builder / `#[must_use]` gaps

| Source file | Item |
|---|---|
| `rust-best-practices.md` | Type-state `AnalyzerBuilder` (replaced by ponytail with simple builder) (now implemented) |
| `rust-remediation-phase-2.md` | `Registry::default` / builder methods — `#[must_use]` not added (now implemented) |
| `rust-remediation-phase-2.md` | Type-state `AnalyzerBuilder<HasRegistry, HasFilter>` (now implemented) |

---

## Documentation / heuristic rules

| Source file | Item |
|---|---|
| `rust-remediation-phase-2.md` | Document heuristic-only rules in registry TOML comment |

---

## Code formatting & size

| Source file | Item |
|---|---|
| `rust-remediation-phase-3.md` | `cargo fmt --check` (still failing) |
| `rust-remediation-phase-3.md` | `cargo fmt` + commit formatting |
| `rust-remediation-phase-3.md` | `scan_entry` orchestrator — 76 lines (target <60) |
| `rust-remediation-phase-3.md` | Trim `scan_entry` orchestrator to <60 lines |

---

## Performance budget

| Source file | Item |
|---|---|
| `rust-remediation-phase-3.md` | Rebaseline or optimize index build for `perf_regression` smoke budget (now implemented) |
