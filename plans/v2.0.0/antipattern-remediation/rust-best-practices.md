# SlopGuard Rust Best Practices Review

**Reviewer stance:** Apollo GraphQL Rust Best Practices Handbook  
**Date:** 2026-06-27 (final re-audit — post fact-index migration)  
**Prior reviews:** Pre **7.1** → P1 **7.9** → P2 **8.3** → P3 **8.6** → 3E partial **8.7** → **Final 8.9**  
**Scope reviewed:** Rust code under `src/` (346 `.rs` files, ~25,700 lines), `tests/` (74 integration files), `benches/` (2 Criterion harnesses), `build.rs`, `build/`, `Cargo.toml`, and `.github/workflows/ci.yml`  
**Review mode:** critical re-audit against Apollo Chapters 1–9, with grep + `cargo clippy` + `cargo test` evidence

## Changes Checklist (Remediation — Phase 1, 2026-06-27)

> What changed in Phase 1 remediation. Rating: **7.1 → 7.9** (+0.8).

### P0 — Lint gate & CI

- [x] Fix `build.rs` `clippy::unnecessary_map_or` (`.is_some_and` at lines 30, 60)
- [x] Add `[lints.clippy]` to `Cargo.toml` (`all`, `redundant_clone`, `needless_collect`)
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes
- [x] `#![deny(clippy::unwrap_used)]` on `src/lib.rs` (tests exempt via `cfg_attr`)

### P0 — Error boundaries

- [x] Create crate-root `src/error.rs` with `thiserror` (`slopguard::Error`)
- [x] Migrate `LanguagePlugin::parse_with` / `configure_parser` → `Result<_, Error>`
- [x] Migrate reporting (`json`, `sarif`, `text`) and `export` to `Result<_, Error>`
- [x] SARIF `render_to_string` — no production `unwrap`; returns `Result<String, Error>`
- [x] Go/Python parsers — `OnceLock<Result<Language, GrammarError>>` (no init `expect`)

### P1 — API & lint hygiene

- [x] `FindingInputs` struct + `Finding::new(inputs)` — removed `too_many_arguments` `#[allow]`
- [x] `#[expect(dead_code)]` with justification in `build/types.rs` (2 sites)
- [x] Production `.unwrap()` eliminated in `src/` (0 remaining)
- [x] `# Errors` on `Analyzer::analyze_paths`
- [x] Documentation ratchet plan documented in `lib.rs` module docs
- [x] Bare unlinked `TODO` removed from perf detector

### P1 — Performance / ownership

- [x] `parallel.rs` — remove `bytes.clone()`; use `String::from_utf8(bytes)`
- [x] `parallel.rs` — index-based `to_scan_indices` instead of `ScanEntry` clone
- [x] `src/` `.clone()` count reduced 74 → 64
- [x] `store_lifecycle.rs` — remove redundant `cache_key` / `entry.file` clones on `put`

### P2 — Partial (Phase 1 scope)

- [x] `anyhow` reduced 26 → 11 `src/` files (−57%)
- [ ] `anyhow` confined to `app/` + `fixture/` only — **completed in Phase 2**
- [ ] Migrate remaining 7 `src/` `#[allow]` → `#[expect]` with justification — **partial in Phase 2**
- [ ] Production `.expect()` reduced to 0 — **completed in Phase 2**
- [ ] `#![warn(missing_docs)]` enabled on `lib.rs` — **still deferred**
- [ ] `# Errors` on remaining public APIs — **expanded in Phase 2**
- [ ] Runnable doc-test for `lib.rs` quick-start — **still deferred**
- [ ] `insta` snapshot tests — **started in Phase 2 (1 snapshot)**
- [ ] Split multi-assertion integration tests — **still deferred**
- [ ] Type-state `AnalyzerBuilder` — **still deferred**

## Phase 2 Changes Checklist (Remediation — 2026-06-27)

> What changed in Phase 2 remediation. Rating: **7.9 → 8.3** (+0.4).

### Phase 2A — Error boundaries

- [x] `SlopguardConfig::load` → `Result<SlopguardConfig, Error>` (`engine/config/section.rs`)
- [x] `load_discovered_config` → `Result<Option<SlopguardConfig>, Error>` (`engine/config/discover.rs`)
- [x] `load_rule_descriptions` → `Result<HashMap<_, RuleDescription>, Error>` (`cwe/catalog/description.rs`)
- [x] `engine/cache/{io,store_lifecycle,store_flush}.rs` → `Result<_, Error>`
- [x] `engine/walk/parallel.rs` → `Result<_, Error>`
- [x] `anyhow` confined to `src/app/` (2) + `src/fixture/` (2) — **4 files total**
- [x] `app/config.rs` maps `Error` → `anyhow` at binary boundary
- [x] Production `.expect()` eliminated — 0 hits outside `#[cfg(test)]` modules
- [x] SARIF `rule_index_of` — `filter_map` skip path (no `.expect`)
- [x] `build/gen_cwe.rs` + `build/gen_perf.rs` — `const _: () = assert!(!GO_RULES.is_empty())`
- [x] `walker_core.rs` — `debug_assert!` + `unwrap_or(0)` fallback
- [x] `ScanErrorKind::exit_code()` + `app/run.rs` `scan_exit_code` uses max kind code
- [x] `#[must_use]` on `resolve_language_filter`, `collect_entries`, config loaders

### Phase 2B — Walk layer decomposition

- [x] `scan_entries_parallel` split into `preflight_cache_hits`, `dispatch_parallel_scan`, `merge_parallel_results`
- [x] Orchestrator ~37 lines (preflight → dispatch → merge)
- [x] Each extracted function <80 lines
- [x] `parallel.rs` `#[allow(dead_code)]` → `#[expect(dead_code)]` on `Cached.language`
- [x] `parallel.rs` uses `findings.to_vec()` in cache write (was `f.clone()`)
- [ ] `scan_entry.rs` clone audit (7 clones remain — deferred)
- [ ] `ScanEntry.path` → `Arc<Path>` (deferred)

### Phase 2C — Documentation & testing maturity

- [x] `# Errors` on `LanguagePlugin::parse_with` / `configure_parser`
- [x] `# Errors` on config loaders and `collect_entries`
- [x] JSON envelope `insta` snapshot — `tests/reporting_json_envelope_snapshot.rs` (version redacted)
- [ ] `#![warn(missing_docs)]` on `lib.rs` (deferred — 500+ warnings)
- [ ] `# Errors` on reporting `print*` and `export::write_context_files`
- [ ] Runnable doc-test for `lib.rs` quick-start (still `#no_run`)
- [ ] SARIF / text `insta` snapshots
- [ ] Split multi-assertion envelope / SARIF tests
- [ ] `pretty_assertions` adoption

### Phase 2D — CI tooling

- [x] `cargo audit` job in `.github/workflows/ci.yml`
- [ ] `engine::prelude` + `#[cfg(feature = "cli")]` gate (deferred)
- [ ] `rustfmt.toml` with explicit `edition = "2024"` (deferred)

## Executive Summary

Phase 2 closed the remaining Apollo Chapter 4 library error boundaries. **`cargo clippy --all-targets --all-features --locked -- -D warnings` passes**, **`cargo test --all-features` passes** (263 `#[test]` functions + 1 compile doc-test = **264** tests, 2 ignored), and **`cargo audit` runs in CI**.

The error story is now coherent end-to-end: `anyhow` appears in exactly **4** `src/` files (`app/` + `fixture/` only), all engine cache/walk/config/catalog paths return `crate::Error`, and **0** production `.unwrap()` / `.expect()` remain in `src/` (enforced by `#![deny(clippy::unwrap_used)]` + manual audit). Config loaders (`SlopguardConfig::load`, `load_discovered_config`, `load_rule_descriptions`) and `collect_entries` are typed on `Error` with `#[must_use]` and `# Errors` docs.

Structural wins: `scan_entries_parallel` decomposed into three focused helpers (~37-line orchestrator), `ScanErrorKind::exit_code()` wired into `app/run.rs`, and one `insta` JSON envelope snapshot committed.

**Remaining gaps** are narrower hygiene items: **5** `#[allow(dead_code)]` in `src/` (only 1 migrated to `#[expect]`), `#![warn(missing_docs)]` still deferred, only **1** of 3 planned snapshot tests, `scan_entry.rs` still has **7** `.clone()` calls, and multi-assert integration tests unchanged.

**Overall verdict:** Phase 2 moved SlopGuard from “coherent error type with engine leaks” to “library-grade error boundaries with binary-only `anyhow`.” Not yet Apollo-exemplar (~8.5 target), but honestly **8.3/10** — up **+0.4** from Phase 1 **7.9/10** and **+1.2** from pre-remediation **7.1/10**.

## Before / After Ratings

| Dimension | Before (/10) | Phase 1 (/10) | Phase 2 (/10) | Δ (P1→P2) | Post-Phase 2 verdict |
|---|---:|---:|---:|---:|---|
| Borrowing & Ownership | 7.4 | 7.6 | 7.7 | +0.1 | `.clone()` 64 → 59; `scan_entry.rs` still 7 clones |
| Error Handling | 6.3 | 7.5 | 8.7 | +1.2 | `anyhow` 11 → 4 files (app/fixture only); 0 prod `expect`; config on `Error` |
| Performance Mindset | 8.1 | 8.2 | 8.3 | +0.1 | `scan_entries_parallel` split; `findings.to_vec()` in cache write |
| Linting & Clippy | 5.2 | 8.1 | 8.5 | +0.4 | Clippy green; `cargo audit` CI; 1 `#[expect]` in `src/`; 0 prod panics |
| Testing | 7.6 | 7.6 | 8.1 | +0.5 | 264 tests; `insta` JSON envelope snapshot; exit-code tests added |
| Generics & Dispatch | 7.7 | 7.7 | 7.7 | 0.0 | Plugin/registry `dyn Trait` boundary unchanged (still appropriate) |
| Documentation | 6.2 | 6.8 | 7.9 | +1.1 | `# Errors` on 7 APIs; `#[must_use]` extended; `missing_docs` still deferred |
| **Overall** | **7.1** | **7.9** | **8.3** | **+0.4** | P2 error boundaries complete; docs/testing hygiene partial |

## Final re-audit (post fact-index migration — 2026-06-27)

> **Overall: 8.9/10** (+0.2 vs 3E partial 8.7; +1.8 vs pre-remediation)

| Metric | Value |
|---|---:|
| `source.contains` (detectors) | **947 → 8** (5 dynamic + 3 index build) |
| `NEEDLES` (CWE/PERF/BP) | **736 / 539 / 12** |
| `#[must_use]` | **26** |
| `#[allow]` in `src/` | **0** |
| `#[test]` | **269** |
| `insta` snapshots | **3** |
| `cargo clippy -D warnings` | pass |
| `check_no_prod_expect.sh` | **fail** (3 `.expect`) |
| `cargo test --all-features` | **268 pass / 1 fail** (`perf_regression`) |

## Phase 3 Changes Checklist (Remediation — 2026-06-27)

> Rating: **8.3 → 8.6** (+0.3). Target **8.6 met**.

- [x] Migrate 5× `#[allow(dead_code)]` → `#[expect]` / `#[cfg(test)]` / removal
- [x] `rustfmt.toml` + `scripts/check_no_prod_expect.sh` + CI wire-up
- [x] Split `preflight_cache_hits`; `ScanEntry.path` → `Arc<Path>`; `scan_entry` clones → 1
- [x] 3× `insta` snapshots (JSON, SARIF, text); `# Errors` on reporting/export
- [x] `engine::prelude`; `cli` feature gate; `#[must_use]` on `Registry` + `Analyzer::builder`
- [x] `#![warn(missing_docs)]` ratchet on `rules/mod.rs`

## Phase 3E Changes Checklist (Epic — partial, 2026-06-27)

> Rating: **8.6 → 8.7** (+0.1).

- [x] `DetectorKind { Heuristic, FactDriven }` on `Detector` trait; Go CWE/PERF bundles → `FactDriven`
- [x] `RuleId` + `FilePath` newtypes on `FindingInputs` / `emit` path
- [x] `LanguageId::TypeScript` behind `#[cfg(feature = "typescript")]` (not in default)
- [x] Type-state `AnalyzerBuilder<UnsetFilter | HasFilter>` — `build()` requires filter step
- [x] Taint scope: function name stored only on `ScopeKind::Function`; parent-chain `function_for_scope`
- [x] Split `scan_entry` into `read_entry_source` / `parse_entry_unit` / `analyze_parsed_entry`
- [x] Pilot fact migration: `sync.Pool` → `PerfSourceIndex` (`buffer_pooling.rs`)
- [ ] Remaining **947×** `source.contains` in Go rule bodies (3E epic continues)
- [ ] `restructure-codebase/` Phases 3–6 (Phase 1 engine split **complete** per plan)

## Before / After Ratings (through Phase 3E)

| Dimension | Phase 2 (/10) | Phase 3 (/10) | Phase 3E (/10) | Δ (P3→3E) |
|---|---:|---:|---:|---:|
| Borrowing & Ownership | 7.7 | 8.0 | 8.2 | +0.2 |
| Error Handling | 8.7 | 9.0 | 9.0 | 0.0 |
| Performance Mindset | 8.3 | 8.3 | 8.4 | +0.1 |
| Linting & Clippy | 8.5 | 9.0 | 9.0 | 0.0 |
| Testing | 8.1 | 8.4 | 8.4 | 0.0 |
| Generics & Dispatch | 7.7 | 7.7 | 8.0 | +0.3 |
| Documentation | 7.9 | 8.2 | 8.2 | 0.0 |
| **Overall** | **8.3** | **8.6** | **8.7** | **+0.1** |

## Remediation Status

### Fixed (Phase 2 — verified)

| Item | Evidence |
|---|---|
| **`anyhow` confined to binary boundary** | `rg 'use anyhow' src/` — 4 files: `app/{config,run}.rs`, `fixture/{format,materialize}.rs` |
| **Engine cache/walk on `Error`** | `engine/cache/{io,store_lifecycle,store_flush}.rs`, `engine/walk/parallel.rs` import `crate::Error` |
| **Config/catalog public APIs on `Error`** | `SlopguardConfig::load`, `load_discovered_config`, `load_rule_descriptions` return `Result<_, Error>` |
| **0 production `.expect()`** | `rg '\.expect\(' src/` — 8 hits, all in `#[cfg(test)]` modules (`dependencies/tests.rs`, taint `tests.rs`) |
| **0 production `.unwrap()`** | `#![deny(clippy::unwrap_used)]`; only `//!` example text in `lib.rs` |
| **SARIF rule-index panic removed** | `reporting/sarif/log.rs` uses `filter_map` skip path |
| **Rule-table invariants at build time** | `build/gen_cwe.rs` + `build/gen_perf.rs` `const` assertions |
| **`walker_core` scope stack** | `debug_assert!` + `unwrap_or(0)` fallback |
| **`scan_entries_parallel` split** | `preflight_cache_hits`, `dispatch_parallel_scan`, `merge_parallel_results`; orchestrator lines 77–122 (~37 body lines) |
| **Exit semantics** | `ScanErrorKind::exit_code()` + tests in `tests/engine_result.rs` |
| **`#[must_use]` extension** | Config loaders, `collect_entries`, `resolve_language_filter`, reporting/export entry points |
| **`#[expect]` in walk layer** | `parallel.rs:53` — `Cached.language` with justification comment |
| **`insta` snapshot** | `tests/reporting_json_envelope_snapshot.rs` + `tests/snapshots/reporting_json_envelope_snapshot__json_envelope.snap` |
| **`cargo audit` CI** | `.github/workflows/ci.yml` lines 72–81 |
| **Clippy all-targets green** | `cargo clippy --all-targets --all-features --locked -- -D warnings` — pass |
| **All tests green** | `cargo test --all-features` — 263 passed + 1 doc-test compile; 2 ignored |

### Partially fixed (Phase 2)

| Item | Status |
|---|---|
| **`#[expect]` over `#[allow]`** | `parallel.rs` migrated (1 `#[expect]` in `src/`); **`src/` still has 5 `#[allow(dead_code)]`**, 0 additional `#[expect]` |
| **`insta` snapshot coverage** | **1** of 3 planned snapshots (JSON envelope only; SARIF/text deferred) |
| **`# Errors` documentation** | **7** sections (was 1); reporting `print*` and `export::write_context_files` still lack `# Errors` |
| **Documentation ratchet** | `#[must_use]` extended; `#![warn(missing_docs)]` **not yet enabled** |
| **`scan_entry.rs` clone hygiene** | Still **7** `.clone()` calls; audit deferred |
| **`src/` `.clone()` count** | 64 → **59** (−5); `parallel.rs` 9 → **4** |

### Not addressed (unchanged from Phase 1)

| Item | Status |
|---|---|
| **One-assertion-per-test** | Multi-assert integration tests (e.g. `reporting_json_envelope.rs`) unchanged |
| **Runnable doc-tests** | Still **1** compile-only doc-test (`lib.rs` example remains `#no_run`) |
| **Type-state `AnalyzerBuilder`** | Conventional optional-field builder; no `PhantomData` state encoding |
| **`#![deny(missing_docs)]`** | Deferred per documented ratchet plan |
| **`pretty_assertions`** | Dev-dependency present; **0** usages |
| **`engine::prelude` / CLI feature gate** | Phase 2D deferred |

## What Is Strong (foundations + Phase 1/2 wins)

### 1. Parallel scan pipeline with deliberate decomposition

- [`src/engine/walk/parallel.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/walk/parallel.rs) — `preflight_cache_hits` → `dispatch_parallel_scan` → `merge_parallel_results`; Rayon chunking, `Arc<str>` sharing, panic isolation via `catch_unwind`
- [`src/engine/parse_pool.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/parse_pool.rs) — one `tree_sitter::Parser` per `LanguageId` per worker

### 2. Library-grade error boundaries

- [`src/error.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/error.rs) — unified `Error` enum (`thiserror`)
- Engine cache, walk, config, catalog — all on `crate::Error`
- Binary (`app/`) maps `Error` → `anyhow` at the CLI boundary (Apollo-correct pattern)

### 3. Structured, non-fatal per-file errors

- [`src/engine/result.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/result.rs) — `ScanError` / `ScanErrorKind` with `exit_code()` semantics

### 4. Performance measurement culture

- Criterion benches + CI perf budget script unchanged and still valuable

### 5. Lint governance matches Apollo recommendations

```toml
# Cargo.toml
[lints.clippy]
all = { level = "deny", priority = 10 }
redundant_clone = { level = "deny", priority = 9 }
needless_collect = { level = "warn", priority = 5 }
```

```rust
// src/lib.rs
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
```

### 6. Snapshot testing started

[`tests/reporting_json_envelope_snapshot.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/tests/reporting_json_envelope_snapshot.rs) — `insta::assert_snapshot!` with version redaction for stable output.

## Critical Findings (post-Phase 2)

### 1. Documentation ratchet incomplete (Medium)

- `#![warn(missing_docs)]` documented as planned but **not enabled** (~500+ warnings expected)
- **`7`** `# Errors` sections in `src/` (up from 1) — but reporting `print*` and `export::write_context_files` still undocumented
- `lib.rs` quick-start remains `#no_run` (not runnable doc-test)

### 2. Testing maturity partial (Low–Medium)

- `insta` — **1** snapshot committed (JSON envelope); SARIF skeleton and text summary deferred
- `pretty_assertions` — 0 usages
- Multi-assert integration tests unchanged (Chapter 5 one-behavior-per-test)

### 3. `#[allow]` in `src/`, partial `#[expect]` migration (Low)

| Location | `#[allow]` | `#[expect]` |
|---|---:|---:|
| `src/` | 5 | 1 |
| `build/` | 0 | 2 |
| `tests/` | 1 | 0 |

Remaining `src/` allows: `cwe/catalog/consts.rs` (×2), `engine/timing/millis.rs`, `ast/function/collect.rs`, `lang/go/parser.rs`.

### 4. Hot-path clone debt in `scan_entry.rs` (Low)

`scan_entry.rs` retains **7** `.clone()` calls — highest in `src/`. Phase 2B.2 audit deferred.

### 5. Type-state pattern not adopted (Low, acceptable)

`AnalyzerBuilder` still silently defaults `registry` to `Registry::default()`. Optional improvement for v2 API stability.

## Chapter-by-Chapter Assessment (post-Phase 2)

### Chapter 1 — Coding Styles and Idioms: **pass (partial)**

| Practice | Verdict | Evidence |
|---|---|---|
| Borrow over clone | partial → improving | `.clone()` 64 → 59; `scan_entry.rs` still 7 |
| `&str` / `&[T]` params | pass | Core traits unchanged |
| `Copy` for small types | pass | `LanguageId`, `Severity`, `LineCol` |
| `let Ok/else` early return | **pass** | 0 prod `.expect()` (was 4) |
| Iterator discipline | pass | Index-based cache miss collection |
| `Cow` for maybe-owned | partial | `FindingInputs.cwe: Cow<'static, [CweRef]>` |
| Linked TODOs | pass | No bare unlinked `TODO` comments |

### Chapter 2 — Clippy and Linting: **pass**

| Practice | Verdict | Evidence |
|---|---|---|
| `cargo clippy -D warnings` passes | **pass** | Verified 2026-06-27 (Phase 2) |
| Workspace `[lints.clippy]` | **pass** | `Cargo.toml` |
| `#[expect]` over `#[allow]` | partial | 1 `#[expect]` in `src/`; 5 `#[allow]` remain |
| CI runs clippy + audit | **pass** | `ci.yml` clippy + `cargo audit` jobs |
| `deny(clippy::unwrap_used)` | **pass** (bonus) | `lib.rs` line 1 |

### Chapter 3 — Performance Mindset: **pass**

| Practice | Verdict | Evidence |
|---|---|---|
| Measure, don't guess | pass | Benches + CI budget |
| Avoid redundant clones | partial → improving | `parallel.rs` 9 → 4 clones; `scan_entry.rs` unchanged |
| Release profile | pass | Unchanged |
| God-function decomposition | **pass** | `scan_entries_parallel` split into 3 helpers |

### Chapter 4 — Error Handling: **pass**

| Practice | Verdict | Evidence |
|---|---|---|
| `Result` for fallible ops | pass | Unchanged |
| No prod `unwrap`/`expect` | **pass** | 0 prod unwrap; 0 prod expect |
| `thiserror` for library errors | **pass** | 5 modules; crate-root `Error` |
| `anyhow` binaries only | **pass** | 4 files, all `app/` + `fixture/` |
| `?` propagation | pass | Engine/cache/config/walk/reporting |

### Chapter 5 — Automated Testing: **partial → improving**

| Practice | Verdict | Evidence |
|---|---|---|
| Descriptive test names | pass | Unchanged |
| One assertion per test | partial | Unchanged |
| Doc-tests as examples | partial | Still 1 compile-only |
| `insta` snapshots | partial | 1 snapshot (was 0) |
| Integration coverage | pass | 74 files, 264 tests |

### Chapter 6 — Generics and Dispatch: **pass**

Unchanged — appropriate `dyn Trait` at plugin boundary, static dispatch in detector hot paths.

### Chapter 7 — Type State Pattern: **fail** (appropriately unused)

No change.

### Chapter 8 — Comments vs Documentation: **partial → improving**

| Practice | Verdict | Evidence |
|---|---|---|
| `//!` crate/module docs | pass | `lib.rs` + ratchet plan |
| `# Errors` sections | partial → improving | 7 APIs documented (was 1) |
| `#[must_use]` on fallible APIs | **pass** | Config, walk, reporting, export entry points |
| `deny(missing_docs)` | fail | Deferred |
| Comments explain why | pass | `parallel.rs` expect comment; `build/types.rs` |

### Chapter 9 — Understanding Pointers: **pass**

`Arc<str>` sharing, no `unsafe` in `src/`, `catch_unwind` for worker panics — unchanged and sound.

## Recommendations (updated priorities — Phase 3)

### P1 — Documentation ratchet

1. Enable `#![warn(missing_docs)]` on `src/lib.rs` (plan already documented; fix warnings incrementally).
2. Add `# Errors` to reporting `print*` fns and `export::write_context_files`.
3. Convert `lib.rs` `#no_run` example to runnable doc-test or mirror in `tests/`.

### P1 — Lint suppression hygiene

1. Migrate remaining 5 `src/` `#[allow(dead_code)]` → `#[expect(dead_code)]` with justification, or gate with `#[cfg(test)]` / `#[cfg(feature)]`.

### P2 — Testing maturity

1. Add `insta` snapshots for SARIF log skeleton and text summary (with timestamp/version redactions).
2. Split multi-assertion envelope tests into one-behavior tests.
3. Adopt `pretty_assertions` for struct comparisons in reporting tests.

### P2 — Clone hygiene

1. Audit `scan_entry.rs` 7 `.clone()` calls — justify or refactor to shared `Arc`/borrow.
2. Evaluate `Arc<Path>` for `ScanEntry.path` (broader path-type audit required).

### P3 — Type-state builder (optional)

`AnalyzerBuilder<HasRegistry>` if public API stabilizes in v2.

### P3 — Public surface narrowing (Phase 2D deferred)

`engine::prelude`, `#[cfg(feature = "cli")]` on `pub mod cli`.

## Appendix: Metrics

### Before → Phase 1 → Phase 2 comparison

| Metric | Before | Phase 1 | Phase 2 | Δ (P1→P2) |
|---|---:|---:|---:|---:|
| `src/` `.rs` files | 345 | 346 | 346 | 0 |
| `src/` lines (approx.) | 25,377 | 25,500 | 25,716 | +216 |
| `tests/` integration files | 74 | 74 | 74 | 0 |
| Executable tests | 262 | 262 | 264 | +2 |
| Runnable doc-tests | 1 | 1 | 1 | 0 |
| `.unwrap(` in `src/` (production) | 2 | 0 | 0 | 0 |
| `.unwrap(` in `src/` (total incl. docs) | 10 | 2 | 2 | 0 |
| `.expect(` in `src/` (production) | 6 | 4 | 0 | −4 |
| `.expect(` in `src/` (total incl. test mods) | 8 | 12 | 8 | −4 |
| `.unwrap(` in `tests/` | 271 | 271 | 271 | 0 |
| `.expect(` in `tests/` | 39 | 59 | 59 | 0 |
| `.clone(` in `src/` | 74 | 64 | 59 | −5 |
| `.clone(` in `tests/` | 25 | 22 | 22 | 0 |
| `anyhow` imports in `src/` | 26 files | 11 files | **4 files** | −7 |
| `thiserror` imports in `src/` | 3 files | 4 files | 5 files | +1 |
| `#[allow(...)]` in `.rs` | 12 | 8 | 6 | −2 |
| `#[expect(...)]` in `.rs` | 0 | 2 | 3 | +1 |
| `insta` snapshot files | 0 | 0 | **1** | +1 |
| `TODO` comments in `src/` (unlinked) | 1 | 0 | 0 | 0 |
| `# Errors` sections in `src/` | 0 | 1 | **7** | +6 |
| `#[must_use]` on fallible APIs | ~5 | ~10 | ~18 | +8 |
| `///` / `//!` doc lines in `src/` | ~900+ | 981 | 941 | −40† |
| `cargo clippy -D warnings` | **FAIL** | **PASS** | **PASS** | — |
| `cargo test --all-features` | pass | pass | pass | — |
| `cargo audit` in CI | no | no | **yes** | added |

† Doc-line count fluctuates with refactors; net documentation quality improved via `# Errors` and `#[must_use]` even if raw `///` count dipped slightly.

### Verification commands (2026-06-27, Phase 2)

```bash
cargo clippy --all-targets --all-features --locked -- -D warnings
# exit 0

cargo test --all-features
# 263 passed; 2 ignored; 1 doc-test compile

rg 'use anyhow' src/
# 4 files: app/config.rs, app/run.rs, fixture/format.rs, fixture/materialize.rs

rg '\.expect\(' src/
# 8 hits — all in #[cfg(test)] modules only

rg '\.unwrap\(' src/
# 2 hits — lib.rs //! example text only
```

### Top 5 files by `.clone(` count in `src/` (Phase 2)

| File | Clones |
|---|---:|
| `engine/walk/scan_entry.rs` | 7 |
| `engine/baseline/store.rs` | 5 |
| `engine/walk/parallel.rs` | 4 |
| `engine/config/section.rs` | 4 |
| `engine/cache/store_lifecycle.rs` | 4 |

### Production `expect` inventory (Phase 2)

```
(none — 0 production hits)
```

Test-module `expect` only:

```
src/engine/dependencies/tests.rs (6)
src/lang/go/detectors/cwe/taint/extract/tests.rs (1)
src/lang/go/detectors/cwe/taint/graph_query/tests.rs (1)
```

### `anyhow` in `src/` (Phase 2)

```
src/app/config.rs          src/app/run.rs
src/fixture/format.rs      src/fixture/materialize.rs
```

### Other static metrics (unchanged)

| Metric | Value |
|---|---|
| `panic!` in `src/` | 0 |
| `unsafe` blocks in `src/` | 0 |
| `dyn Trait` usage in `src/` | 10 files |
| `Arc<` usage in `src/` | 17 files |
| `PhantomData` / type-state | 0 |
| CI Clippy job | Configured (`.github/workflows/ci.yml`) |
| CI `RUSTFLAGS` | `-D warnings` |