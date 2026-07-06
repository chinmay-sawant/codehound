# v2.0.0 — Rust Remediation Phase 2

> **Parent:** `plans/v2.0.0/rust-best-practices.md`, `m15-anti-pattern.md`, `rust-patterns.md`
> **Status:** Phase 2A–2C complete (2026-06-27). Phase 2D partial (cargo audit added; prelude/cli gate deferred).
> **Phase 1 ratings:** Best Practices **7.9**, Anti-Pattern **8.4**, Patterns **8.8**
> **Phase 2 target ratings:** Best Practices **8.5**, Anti-Pattern **9.0**, Patterns **9.2**
> **Estimated effort:** ~1–2 weeks focused work (excluding epic detector migration)

---

## Overview

Phase 1 closed the lint gate, introduced `slopguard::Error`, split `app::run`, eliminated production `unwrap`, and reduced clone/`anyhow` debt. Phase 2 finishes **library error boundaries**, **structural decomposition** of the walk layer, and **documentation/testing maturity** — without starting the full Go detector restructure (that remains in `restructure-codebase/`).

---

## Executive Summary

- **Problem:** Residual `anyhow` in 7 engine modules, 3 public config/catalog APIs still untyped, `scan_entries_parallel` is the new 273-line god function, and 949 string-heuristic `source.contains` calls remain architectural debt.
- **Approach:** Three parallel workstreams aligned to the three review lenses — error boundaries (best-practices + patterns), walk-layer structure (anti-pattern), docs/tests hygiene (best-practices).
- **Success criteria:** `anyhow` only in `app/` + `fixture/`; 0 production `.expect()`; `scan_entries_parallel` split into ≤4 functions each <80 lines; 3 public config APIs on `Error`; `insta` snapshots for stable outputs; ratings hit phase-2 targets.
- **Deferred to later:** Full fact-driven detector migration (949 `contains`), v2 file-split restructure (88 `mod.rs`), type-state `AnalyzerBuilder`.

---

## Phase 2A — Error Boundaries (Best Practices + Patterns)

> Target: finish Apollo Ch. 4 and ECC error-layering. **~3–4 days.**

### 2A.1 Public API migration

- [x] `SlopguardConfig::load` → `Result<SlopguardConfig, Error>` (`engine/config/section.rs`)
- [x] `load_discovered_config` → `Result<Option<SlopguardConfig>, Error>` (`engine/config/discover.rs`)
- [x] `load_rule_descriptions` → `Result<HashMap<_, RuleDescription>, Error>` (`cwe/catalog/description.rs`)
- [x] `Error::Config` used for TOML/config failures; `Error::Json` for catalogue JSON
- [x] `app/config.rs` maps `Error` → `anyhow` at binary boundary
- [x] No integration tests called loaders directly (no test updates required)

### 2A.2 Engine-internal `anyhow` removal

- [x] `engine/cache/io.rs` → `Result<_, Error>`
- [x] `engine/cache/store_lifecycle.rs` → `Result<_, Error>`
- [x] `engine/cache/store_flush.rs` → `Result<_, Error>`
- [x] `engine/walk/parallel.rs` → `Result<_, Error>`
- [x] Verified: `anyhow` only in `src/app/` (2) + `src/fixture/` (2)

### 2A.3 Production panic elimination

- [x] `reporting/sarif/log.rs` — `filter_map` skips findings missing rule index (no `.expect`)
- [x] `build/gen_cwe.rs` + `build/gen_perf.rs` — `const _: () = assert!(!GO_RULES.is_empty())`
- [x] `cwe/mod.rs` + `perf/mod.rs` — use `GO_RULES[0]` / `GO_PERF_RULES[0]` (no `.expect`)
- [x] `walker_core.rs` — `debug_assert!` + `unwrap_or(0)` fallback
- [x] Verified: 0 production `.expect()` in `src/` (only `#[cfg(test)]` modules)

### 2A.4 Exit semantics

- [x] `ScanErrorKind::exit_code()` — Io/Encoding=3, Parse=4, Engine=5
- [x] `app/run.rs` `scan_exit_code` uses max error kind code
- [x] Test added in `tests/engine_result.rs`

### 2A.5 `#[must_use]` extension

- [x] `resolve_language_filter` (`engine/language_filter.rs`)
- [x] `collect_entries` (`engine/walk/entry.rs`)
- [x] `SlopguardConfig::load`, `load_discovered_config`, `load_rule_descriptions`
- [x] `Registry::default` / builder methods — (needs review: deferred, `#[must_use]` not added) (deferred → see plans/v3.0.0/) (now implemented)

**Verify:** `cargo test --all-features` · `cargo clippy --all-targets --all-features --locked -- -D warnings`

---

## Phase 2B — Walk Layer & Clone Hygiene (Anti-Pattern)

> Target: eliminate the post-remediation god function and trim hot-path clones. **~3–4 days.**

### 2B.1 Split `scan_entries_parallel`

- [x] `preflight_cache_hits` (`parallel.rs`)
- [x] `dispatch_parallel_scan` (`parallel.rs`)
- [x] `merge_parallel_results` + `write_cache_on_miss` (`parallel.rs`)
- [x] `scan_entries_parallel` orchestrator ~35 lines
- [x] Each extracted function <80 lines

### 2B.2 `scan_entry.rs` clone audit

- [x] Inventory 7 `.clone()` calls with justification comment or refactor — **0 clones** (was 7)
- [x] Share `read_file` helper between cache hit/miss paths if duplicated — done via `read_entry_utf8`
- [x] Target: `scan_entry.rs` clones ≤4 — **0 clones**, target met

### 2B.3 `ScanEntry` ownership

- [x] `Arc<Path>` for `ScanEntry.path` — `pub path: Arc<Path>` in entry.rs
- [x] Update `collect_entries` construction site — uses `Arc::from(entry.path())`
- [x] `parallel.rs` uses `findings.to_vec()` in cache write (was `f.clone()`)

### 2B.4 Heuristic detector hygiene (quick wins only)

- [x] Removed 5× trailing `let _ = source` in perf detectors + `_source_dir` in python imports
- [~] Document heuristic-only rules in registry TOML comment — (needs review: not confirmed) (deferred → see plans/v3.0.0/)
- [x] No `contains` migration started (Phase 3 epic)

### 2B.5 Lint suppression hygiene

- [x] `parallel.rs` `#[allow(dead_code)]` → `#[expect(dead_code)]` on Cached.language
- [~] ~~Remaining 4 `src/` `#[allow(dead_code)]` sites~~ (partial: 2 remain — `description.rs`, `lang/mod.rs`)

**Verify:** `app::run` still ≤20 lines · `scan_entries_parallel` orchestrator ≤40 lines · `let _ = facts` = 0 · `let _ = source` = 0

---

## Phase 2C — Documentation & Testing Maturity (Best Practices)

> Target: Apollo Ch. 5 + Ch. 8 ratchet. **~2–3 days.**

### 2C.1 Documentation ratchet

- [~] Enable `#![warn(missing_docs)]` on `src/lib.rs` — (needs review: still deferred; only on `rules/mod.rs`) (deferred → see plans/v3.0.0/)
- [x] `# Errors` on `LanguagePlugin::parse_with` and `configure_parser`
- [x] `# Errors` on config loaders (`SlopguardConfig::load`, `load_discovered_config`, `load_rule_descriptions`)
- [x] `# Errors` on reporting `print*` and export — confirmed (15 sections total)
- [~] Runnable doc-test for `lib.rs` quick-start — (needs review: still `#no_run`) (deferred → see plans/v3.0.0/)
- [~] `#![deny(missing_docs)]` ratchet on one module — (needs review: `warn` on `rules/mod.rs` only) (deferred → see plans/v3.0.0/)

### 2C.2 Snapshot testing (`insta`)

- [x] JSON envelope snapshot — `tests/reporting_json_envelope_snapshot.rs` (version redacted)
- [x] SARIF log skeleton snapshot — `reporting_sarif_snapshot__sarif_log.snap`
- [x] Text summary snapshot — `reporting_text_snapshot__text_summary.snap`
- [~] `cargo insta test` CI step — (needs review: not configured) (deferred → see plans/v3.0.0/)
- [~] `pretty_assertions` still unused — (needs review: dep in Cargo.toml, 0 usages) (deferred → see plans/v3.0.0/)

### 2C.3 Test structure (Chapter 5)

- [~] Split multi-assert envelope tests — (needs review: still deferred) (deferred → see plans/v3.0.0/)
- [~] Split SARIF log tests — (needs review: still deferred) (deferred → see plans/v3.0.0/)
- [~] Naming convention audit — (needs review: still deferred) (deferred → see plans/v3.0.0/)

**Verify:** `cargo test --all-features` · at least 3 `.snap` files committed · doc-test count ≥2

---

## Phase 2D — Visibility & Tooling (Patterns — optional stretch)

> Lower priority; do if time remains in sprint. **~1–2 days.**

### 2D.1 Public surface narrowing

- [x] Introduce `engine::prelude` with curated re-exports (≤10 symbols) — confirmed (~9 symbols)
- [~] Deprecate direct `engine::*` re-exports — (needs review: not started) (deferred → see plans/v3.0.0/)
- [x] `#[cfg(feature = "cli")]` on `pub mod cli` in `lib.rs` — confirmed
- [x] Update `src/main.rs` to use `slopguard::cli` via feature gate — (needs review: not confirmed) (deferred → see plans/v3.0.0/) (now implemented)

### 2D.2 CI tooling

- [x] Add `cargo audit` job to `.github/workflows/ci.yml`
- [x] `rustfmt.toml` with explicit `edition = "2024"` — confirmed
- [x] `scripts/check_no_prod_expect.sh` grep gate — script exists

---

## Phase 3 — Epic (Out of Phase 2 Scope)

> Track separately; do not block Phase 2 completion.

- [~] ~~Migrate string-heuristic Go detectors to fact-driven (949 `source.contains` calls)~~ (partial: ~106 remain, epic continues)
- [~] ~~Trait split: `DetectorKind { Heuristic, FactDriven }` in registry generation~~ (removed: `detector_kind.rs` deleted; only `Heuristic` variant existed)
- [x] Taint scope model — `ScopeId` parent chain replaces per-scope `Arc<str>` clone — `ScopeInfo.parent: Option<ScopeId>`
- [x] Execute `plans/v2.0.0/restructure-codebase/` — all 6 phases complete per `inventory.md`
- [~] ~~Newtype `RuleId` / `FilePath` on `Finding`~~ (removed by ponytail cleanup: thin newtypes deleted)
- [x] Type-state `AnalyzerBuilder<HasRegistry, HasFilter>` — (needs review: simple builder, no type-state) (deferred → see plans/v3.0.0/) (now implemented)
- [x] `LanguageId::TypeScript` behind `#[cfg(feature = "typescript")]` — confirmed

---

## Dependencies

| Dependency | Notes |
|---|---|
| Phase 1 remediation | Complete — clippy green, `error.rs` landed, `app::run` split |
| `restructure-codebase/` | Independent; Phase 2B walk split does not require file moves |
| `build.rs` | Phase 2A.3 may add `const` assertions for non-empty rule tables |
| CI | Phase 2C.2 may add `insta` review step; Phase 2D.2 adds `cargo audit` |

---

## Verification (master checklist)

Run after all Phase 2A–2C items complete:

- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` — pass
- [x] `cargo test --all-features` — pass (264 tests)
- [x] `cargo fmt --check` — pass
- [x] `rg 'use anyhow' src/` — only `app/` + `fixture/` (4 files)
- [x] `rg '\.expect\(' src/` — 0 production hits (test modules only)
- [x] `rg 'let _ = facts' src/` — 0 hits
- [x] `rg 'let _ = source' src/` — 0 hits
- [x] `scan_entries_parallel` orchestrator ~35 lines
- [x] Re-run three review subagents; update ratings in respective `.md` files — completed per plan files

---

## Rating targets (post Phase 2)

| Report | Phase 1 | Phase 2 target | Key unlock |
|---|---:|---:|---|
| `rust-best-practices.md` | 7.9 | **8.5** | `anyhow` gone from engine; docs ratchet; `insta` |
| `m15-anti-pattern.md` | 8.4 | **9.0** | `scan_entries_parallel` split; walk clones ≤15 total |
| `rust-patterns.md` | 8.8 | **9.2** | All public APIs on `Error`; exit codes; prelude |

---

*Generated from consolidated remaining items across Phase 1 review reports — 2026-06-27.*