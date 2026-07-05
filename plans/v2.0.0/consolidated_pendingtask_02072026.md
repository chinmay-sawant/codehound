# Consolidated Pending Tasks — 2026-07-02

> **Status:** Living document — priorities, checklists, and phase plans for all remaining work
> **Estimated effort:** ~12–14 weeks total across all workstreams

---

## Overview

Consolidated view of all pending implementation work across CWE taint tracking,
PERF detectors, and Bad Practices detection. Items are grouped by priority
tier and phase within each workstream.

---

## Executive Summary

| Workstream | Priority | Status | Remaining Effort | Key Deliverable |
|------------|----------|--------|-----------------|-----------------|
| CWE-90/91 Taint Rewrite | P0 | ✅ Complete | 0 | Taint-gated CWE-90/91 detectors |
| Taint Phase C–F | P1 | Phases C/D/E complete, F sub-plan ready | 3–4 weeks | Inter-procedural taint tracking |
| PERF Detectors | P2 | ✅ Complete | 0 | Benchmark regression, docs, fixture audit, edge-case hardening |
| Bad Practices (BP) | P3 | ✅ Complete (65/63 shipped) | 0 | All 65 BP rules shipped |
| Cross-cutting | P4 | Partial | 2 weeks | Docs, CI gates, schema updates |

---

## P0 — CWE-90/91: Taint Path Integration ✅ COMPLETED

> **Status:** Both detectors are taint-gated (2026-07-03). CWE-90/91 use the same
> `TaintGraph` path-finding infrastructure as CWE-22/78/79/89. Fixture regressions
> from the taint-enabled-by-default switch are fixed across all safe fixtures.

### Phase 1: Taint-gated CWE-90/91 ✅

- [x] Add `SinkKind::LDAPQuery` to `model.rs`
- [x] Add `SinkKind::XMLQuery` to `model.rs`
- [x] Add LDAP sink matchers: `ldap.Dial`, `ldap.Search`, `ldap.SearchByAttribute`, `ldap.NewSearchRequest`
- [x] Add XML sink matchers: `xml.Unmarshal`, `.DecodeElement` (before generic Deserialization)
- [x] Add LDAP sanitizer: `ldap.EscapeFilter` → `SanitizerKind::LDAP`
- [x] Add XML sanitizers: `xml.EscapeText`, `xml.Marshal` → `SanitizerKind::XML`

### Phase 2: Detector rewrite ✅

- [x] Create `rules/cwe_90.rs` following `cwe_78.rs` taint pattern
- [x] Create `rules/cwe_91.rs` following `cwe_89.rs` taint pattern
- [x] Wire both in `rules/mod.rs` and `taint/mod.rs`
- [x] Add taint-gated delegation in `sinks.rs` with substring fallback
- [x] Updated fixture vulnerable patterns from generic `dial` to `ldap.Search`
- [x] Over-tainting fix: `is_sink_call_by_name` prevents sink return values from being tainted by arguments

### Phase 3: Test fixtures ✅ (existing fixtures updated, new taint fixtures deferred)

- [x] Updated existing CWE-90 vulnerable fixtures (both frameworks/stdlib) to use `ldap.Search` / `ldap.NewSearchRequest`
- [x] Updated existing CWE-79 vulnerable fixtures to use `text/template.Execute` (Template sink)
- [x] CWE-90/91 vulnerable fixtures pass `taint_cwe_fixtures_fire_vulnerable_and_silence_safe`

### Phase 4: Edge-case hardening ✅ (deferred to P0 follow-up)

- [x] Over-tainting regression from taint-by-default: fixed 7 safe fixtures with `filepath.Base()` / `html.EscapeString()`
- [x] Dual-edge issue: source+sanitizer claiming same `result_variable` → temp variable pattern (`raw := src(); safe := sanitizer(raw)`)
- [x] Substring collision: `/data/patients/` matching variable `data` in `referenced_identifiers` → renamed variable to `jsonData`

---

## P1 — Taint Tracking: Phases C–F

> **Parent:** `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md`
> **Status:** Phase C/E shipped (2026-07-03). D/F not started.

### Phase C — Remove substring fallback ✅ SHIPPED

- [x] Land Phase E (CLI flags) so users can discover and enable taint without editing `slopguard.toml`
- [x] Flip default `slopguard.taint.enabled` from `false` to `true`
  - Also fixed `build_scan_context` hardcoded default (was `false`, now `true`)
  - Also fixed `TaintConfig.enabled` from `bool` to `Option<bool>` so config absence doesn't override
- [x] Remove substring fallback in CWE-22/78/79/89:
  - CWE-78/79/89: removed entirely, delegate straight to taint
  - CWE-22: kept `if taint_graph.is_some() { taint } else { fallback }` as safety net when taint is explicitly disabled
- [x] Fixed taint graph sink wiring for compound args (`"prefix" + var` — `build.rs`)
- [x] Added `os.ReadFile`, `ioutil.ReadFile` to taint sink classifier (CWE-22 regression)
- [~] Add a `cargo test --all-features` run with taint enabled to CI (deferred → see plans/v3.0.0/)

### Phase D — Extended sanitizer coverage

- [x] Run `make lint` / `make fmt` and fix all 7 clippy errors + formatting (2026-07-03)
- [x] `strconv.Atoi`, `strconv.ParseInt`, `strconv.ParseFloat`, `strconv.ParseUint` → `SanitizerKind::Validation`
- [x] `html.UnescapeString` → `SanitizerKind::HTML`
- [x] Name-based heuristic: functions matching `/^(sanitize|clean|escape|validate|purify)/i` → `SanitizerKind::Validation`
- [ ] ~~`utf8.ValidString` → `Validation`~~ (skipped: returns bool, no sanitized value produced for taint graph)
- [ ] ~~`net/url.IsAbs` → `URL`~~ (skipped: returns bool)
- [ ] ~~`strings.HasPrefix`/`HasSuffix`/`Contains` → `Validation`~~ (skipped: return bools, control-flow not modeled by taint graph)
- [ ] ~~Gin/Echo framework bind sanitizers~~ (skipped: side-effect pattern, sanitized data in pointer arg not return value)

### Phase E — CLI flags + docs ✅ SHIPPED

- [x] `--taint` flag: enable taint tracking from CLI
- [x] `--no-taint` flag: disable taint even if config enables it
- [x] `--taint-show-paths` flag: emit taint-path evidence in JSON/SARIF/text output
- [x] Wire `taint_show_paths` in JSON reporter (`evidence.taint_path`)
- [x] Wire `taint_show_paths` in SARIF reporter (`properties` bag)
- [x] Wire `taint_show_paths` in text reporter (print path in output)
- [x] Create `docs/taint.md` — overview, enabling, model, limitations, output, custom sanitizers
- [x] Update `templates/slopguard.toml` with commented-out `[slopguard.taint]` block

### Phase F — Inter-procedural taint tracking

> **Sub-plan:** `plans/p1f-inter-procedural-taint.md` — 6 phases, ~46 detailed checklist items.
> **Estimated effort:** 3–4 weeks.

- [x] Phase 1: Call graph construction (per-file + project-level merge)
- [x] Phase 2: Function summary computation (`TaintSummary` struct)
- [x] Phase 3: Cross-function propagation (call-site wiring, fixed-point iteration)
- [x] Phase 4: Evidence and reporting (multi-hop path display)
- [x] Phase 5: Tests and fixtures (10+ inter-procedural fixture pairs)
- [x] Phase 6: Edge-case handling (recursion, pointers, maps, goroutines, deferred calls)

---

## P2 — PERF Detectors: Remaining Hygiene ✅ COMPLETED

> **Parent:** `plans/p2-implementation/04-perf-detector-implementation.md`
> **Status:** 109/112 rules shipped. 3 intentionally dropped. All Category A/B/C done.
> **Hygiene:** Complete (2026-07-03).
> **Sub-plan:** `plans/p2-hygiene-subplan.md` — detailed breakdown with per-phase checklists

### Phase 1 — Benchmark regression investigation ✅

- [x] Investigate criterion bench regression noted in P2.4 batch 3 (see sub-plan §1.3)
- [x] Verify cold/warm/partial/in-memory benchmarks are within 20% of saved local baseline (see sub-plan §1.1)
- [x] Document findings in `docs/architecture-performance.md` if regression is structural (see sub-plan §1.4)

### Phase 2 — Diagnostic docs ✅

- [x] Create `docs/perf-detector-development.md` (see sub-plan §2.1 for detailed structure)
  - Registry TOML format, domain module layout, function-pointer dispatch
  - Fixture creation pattern, `manifest.toml` registration
  - Build.rs codegen and testing
- [x] Self-verify the guide by tracing a hypothetical PERF-213 rule end-to-end (see sub-plan §2.2)

### Phase 3 — Test fixture hygiene ✅

- [x] Audit all 209 fixture pairs for consistency (see sub-plan §3.1–3.4):
  - Every fixture has a proper `lang:` header and `---` separator
  - Every fixture is registered in `tests/fixtures/manifest.toml`
  - No stale `.txt` fixture files without corresponding rule implementation
  - Vulnerable-safe pair completeness
- [x] Fix any inconsistencies found (stdlib CWE-279-safe path traversal fixed)

### Phase 4 — Edge-case hardening for selected rules ✅

- [x] PERF-172: verified `wg.Wait` suppression — goroutine with real work call suppresses (covered by existing safe fixture)
- [x] PERF-150: verified large stack frame detection skips type declarations (covered by existing detector logic)
- [x] PERF-139: verified closure escape in non-handler contexts (covered by `is_request_path` filter)

---

## P3 — Bad Practices: BP-16..BP-65 + Metadata Refactor

> **Parent:** `plans/p2-implementation/05-bad-practices-detection.md`
> **Status:** 13/63 rules shipped (MVP). 50 rules not started. Metadata refactor pending.
> 2 rules reserved for taint.

### Phase 1 — MVP Hygiene (2–3 days) ✅

- [x] Add dedicated `tests/go_bad_practice_integration.rs` with fixture-driven tests
- [x] Create `tests/helpers/go_bp_cases.rs` helper for fixture discovery
- [x] Remove BP-specific checks from generic tests (`engine_config_cli_filters.rs`, `reporting_json_finding.rs`)
- [x] Add BP-15 regression test: recursive `sync.Once.Do()` via separate function (not just direct closure)

### Phase 2 — Metadata Refactor (2–3 days) ✅

- [x] Create `BadPracticeCategory` enum in `src/rules/bp_category.rs`
- [x] Create `ruleset/golang/bad-practices.json` with same structure as `golang.json`
- [x] Add `gen_bp.rs` in `build/` for BP codegen
- [x] Replace inline constants in `metadata.rs` with `include!` of generated code

### Phase 3 — Testing Anti-Patterns: BP-16..BP-25 (1 week) ✅

> All rules fire only in `*_test.go` files.

- [x] **BP-16**: `time.Sleep` in test (not in retry loop)
- [x] **BP-17**: `t.Error` followed by `t.Fatal` (redundant)
- [x] **BP-18**: `t.Error` / `t.Errorf` without `t.FailNow` / `return`
- [x] **BP-19**: Missing `t.Helper()` on test helper functions
- [x] **BP-20**: Table-driven test without `t.Run`
- [x] **BP-21**: `t.Parallel()` missing in table-driven subtest
- [x] **BP-22**: TestMain without `os.Exit`
- [x] **BP-23**: `testing.Short()` not checked for long tests
- [x] **BP-24**: Test file without any test functions
- [x] **BP-25**: Test helper returns error instead of calling `t.Fatal`
- [x] Create `rules/testing.rs` with detection functions
- [x] Create 20 fixture files (10 vulnerable + 10 safe, using `_test.go` suffix)
- [x] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`

### Phase 4 — API Design + Code Organization: BP-26..BP-45 (2 weeks) ✅

> Requires tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`.

- [x] **BP-26**: Context not first parameter
- [x] **BP-27**: Exported function returns unexported type
- [x] **BP-28**: Interface with single method (should be func type)
- [x] **BP-29**: Interface bloat (>5 methods)
- [x] **BP-30**: Exported interface without documented implementation
- [x] **BP-31**: Function returns concrete type instead of interface
- [x] **BP-32**: Error type as `string` instead of `struct`
- [x] **BP-33**: Sentinel error without `Is` method
- [x] **BP-34**: Error wrapping without `%w`
- [x] **BP-35**: Package name != directory name
- [x] **BP-36**: `init()` with side effects
- [x] **BP-37**: Package-level mutable global variable
- [x] **BP-38**: Unexported helper with no internal callers
- [x] **BP-39**: Exported function without doc comment
- [x] **BP-40**: Package-level block with unrelated constants
- [x] **BP-41**: File header missing package doc comment
- [x] **BP-42**: Import alias not used consistently
- [x] **BP-43**: Dot import outside test files
- [x] **BP-44**: Blank import without justification
- [x] **BP-45**: Receiver name inconsistent across methods
- [x] Create `rules/api_design.rs` and `rules/code_organization.rs`
- [x] Create 40 fixture files (20 vulnerable + 20 safe)

### Phase 5 — Production Hardening + Dependency Hygiene: BP-46..BP-65 (2 weeks) ✅

> Some rules co-developed with P2.1 taint.

- [x] **BP-46**: HTTP server without `ReadTimeout`/`WriteTimeout`
- [x] **BP-47**: No graceful shutdown
- [x] **BP-48**: `log.Fatal`/`os.Exit` in non-main function
- [x] **BP-49**: Deferred function without error handling
- [x] **BP-50**: No signal handling for `SIGTERM`/`SIGINT`
- [x] **BP-51**: Panic recovery without re-panic in library code
- [x] **BP-52**: Integer overflow in arithmetic (heuristic)
- [x] **BP-53**: `encoding/gob` registered types not matching
- [x] **BP-54**: No rate limiting on public HTTP endpoint
- [x] **BP-55**: Missing `RequestID` propagation in middleware chain
- [x] **BP-56**: Deprecated stdlib package used
- [x] **BP-57**: Old Go version in `go.mod`
- [x] **BP-58**: Unpinned dependency version
- [x] **BP-59**: Direct dependency not used in any import
- [x] **BP-60**: Test dependency in main `go.mod`
- [x] **BP-61**: Indirect dependency not listed in `go.mod`
- [x] **BP-62**: Dependency used only in one file
- [x] **BP-63**: Dependency with known CVE not updated
- [x] **BP-64**: Replace directive pointing to local filesystem
- [x] **BP-65**: `go.sum` missing entries
- [x] Create `rules/production_hardening.rs` and `rules/dependency_hygiene.rs`
- [x] Create fixture files + fixture directories (for project-level rules)

### Phase 6 — Documentation ✅

- [x] Create `docs/bad-practices.md` — one paragraph per BP rule with rationale and canonical fix

---

## P4 — Cross-Cutting

- [x] Add `--taint` / `--no-taint` / `--taint-show-paths` to CLI (Phase E prerequisite for C and P0)
- [x] Create `docs/taint.md`
- [x] Create `docs/bad-practices.md`
- [x] Create `docs/perf-detector-development.md`
- [x] Add CWE-90/91 fixtures to `tests/fixtures/manifest.toml`
- [~] Run `cargo test --all-features` after each phase (deferred → see plans/v3.0.0/)
- [x] Run `cargo clippy --all-targets --all-features -- -D warnings` after each phase

---

## Dependency Graph

```
P0 (CWE-90/91 taint)
  └─ depends on existing TaintGraph infra (Phases A/B) ✅ DONE

P1-C (remove substring fallback)
  └─ BLOCKED on P1-E (CLI flags)

P1-D (extended sanitizers)
  └─ independent, can parallel with P1-E

P1-E (CLI flags + docs)
  └─ no deps, HIGHEST LEVERAGE

P1-F (inter-procedural)
  └─ depends on P1-A/B ✅ DONE, separate sub-plan needed

P2 (PERF hygiene)
  └─ independent, pure maintenance

P3 (BP expansion)
  └─ Phases 1–2 independent
  └─ Phases 3–5 depend on BP architecture
  └─ Phase 5 (BP-46..BP-65) may overlap with P1 taint

P4 (cross-cutting)
  └─ docs depend on feature completion
```

## Quick Reference

| Priority | Workstream | Rules | Effort | Blocked By |
|----------|-----------|-------|--------|------------|
| **P0** | CWE-90/91 taint rewrite | 2 rules | ✅ Complete | — |
| **P1-C** | Taint: remove substring fallback | 4 CWEs | ✅ Complete | — |
| **P1-D** | Taint: extended sanitizers | ~10 matchers | ✅ Complete | — |
| **P1-E** | Taint: CLI flags + docs | 3 flags + 1 doc | ✅ Complete | — |
| **P1-F** | Taint: inter-procedural | — | 3–4w | Sub-plan at `plans/p1f-inter-procedural-taint.md` |
| **P2** | PERF hygiene (bench reg, docs, audit) | — | ✅ Complete | — |
| **P3** | Bad Practices (all phases) | 65 rules | ✅ Complete | — |
| **P4** | Cross-cutting docs + CI | `perf-detector-dev.md` + CI | 1w | — |
