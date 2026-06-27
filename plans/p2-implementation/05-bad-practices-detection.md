# P2.5 — Bad Practices Detection (Implementation Status)

> **Parent:** `plans/p2.md` — P2.5
> **Status:** ✅ **MVP implemented** (v2.0.0 remediation). Phases 2–4 (Testing, API Design, Code Org, Production Hardening, Dependency Hygiene) **not started**.
> **Estimated effort:** MVP was ~1 week. Remaining phases ~6 weeks total.
> **See also:** `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md` (original scoping doc), `plans/v2.0.0/rust-remediation-phase-3.md` (remediation tracking)
> **Pending work breakdown:** `plans/v2.0.0/pending-work/03-bad-practices-remaining.md`

---

## Overview

Bad Practices detection is a new rule category beyond CWE (security) and PERF (performance), covering general Go software engineering anti-patterns. The MVP (BP-1..BP-15) was implemented as part of the v2.0.0 remediation. This plan tracks what's built and what remains.

---

## Executive Summary

- **13 rules implemented** across 4 domain modules: `error_handling`, `sync`, `loops`, `panics`.
- **Architecture:** Single `GoBadPracticeScan` detector (Option A) with a `SourceIndex` fact pre-filter and per-rule dispatch table — mirrors the CWE/PERF pattern.
- **Gaps vs. original plan:** No `ruleset/golang/bad-practices.json` (metadata is inline), no `build.rs` codegen, no `BadPracticeCategory` enum (uses `category_for_rule_id()` string matching), no `--bp-only` flag (uses `--only BP-*`).
- **Remaining:** 5 sub-categories not started (Testing, API Design, Code Org, Production Hardening, Dependency Hygiene). BP-12 and BP-14 (goroutine leak detection) still reserved for taint-driven implementation.

---

## Phase 1: Scope Definition (COMPLETED)

### 1.1 Research conducted

- [x] Go Wiki — CommonMistakes
- [x] Go CodeReviewComments
- [x] 100 Go Mistakes catalog patterns
- [x] Uber Go Style Guide anti-patterns
- [x] Google Go Style Guide decisions
- [x] Effective Go "Don't do this" sections
- [x] Dave Cheney's blog posts
- [x] staticcheck / go-critic / revive rule lists
- [x] gosec non-security checks
- [x] Catalog documented in `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md`

### 1.2 Sub-categories defined

- [x] **Error Handling** — BP-1..BP-5 (MVP)
- [x] **Concurrency** — BP-6..BP-15, BP-12/BP-14 reserved (MVP)
- [ ] **Testing** — BP-16..BP-25 (not started)
- [ ] **API Design** — BP-26..BP-35 (not started)
- [ ] **Code Organization** — BP-36..BP-45 (not started)
- [ ] **Production Hardening** — BP-46..BP-55 (not started)
- [ ] **Dependency Hygiene** — BP-56..BP-65 (not started)

### 1.3 Scope criteria applied

- [x] Statically detectable (AST/pattern-based)
- [x] Not already covered by CWE/PERF rules
- [x] Not already covered by `go vet` / `staticcheck` defaults
- [x] High-signal, low-noise
- [x] Out-of-scope documented (stylistic, language-level vet checks, runtime patterns)

### 1.4 Rule ID scheme selected

- [x] Prefix: `BP-N` (Bad Practice)
- [x] Sequential numbering within each sub-category block
- [x] Implemented: BP-1..BP-11, BP-13, BP-15 (gaps at BP-12, BP-14 — reserved)

---

## Phase 2: Detection Strategy (MVP IMPLEMENTED)

### 2.1 Detector architecture

- [x] **Option A chosen** — single `GoBadPracticeScan` detector with domain submodules
- [x] Located at `src/lang/go/detectors/bad_practices/mod.rs:13`

### 2.2 Rule metadata

- [x] Inline `RuleMetadata` constants in `src/lang/go/detectors/bad_practices/metadata.rs`
- [ ] `ruleset/golang/bad-practices.json` — **not created** (metadata is source-level only)
- [ ] `build.rs` codegen for BP metadata — **not implemented** (inline constants used instead)

### 2.3 Detection approach per sub-category (MVP)

**Error Handling:**
- [x] BP-1: AST walk for `assignment_statement` / `short_var_declaration` with `_ =` discard pattern — `error_handling.rs:11`
- [x] BP-2: Line scan for `return err` without wrapping — `error_handling.rs:57`
- [x] BP-3: AST walk for `panic()` outside `main()` / test files — `panics.rs:11`
- [x] BP-4: Source-index pre-filter for `recover()` + heuristic logging check — `error_handling.rs:76`
- [x] BP-5: Line scan for `.Close()` return ignored — `error_handling.rs:106`

**Concurrency:**
- [x] BP-6: Line scan for `go func`..`.Add(` inside goroutine body — `sync.rs:9`
- [x] BP-7: Line scan for `func` param with `sync.Mutex` by value — `sync.rs:40`
- [x] BP-8: Source-index pre-filter for `defer`..`.Unlock()` — `sync.rs:64`
- [x] BP-9: Block scan for `select { }` without `default:` / timeout / ctx — `sync.rs:87`
- [x] BP-10: AST walk for `time.After()` inside loop — `loops.rs:11`
- [x] BP-11: AST walk for `defer_statement` inside loop — `loops.rs:48`
- [x] BP-13: AST function-stack for `context.Background()` in library — `panics.rs:67`
- [x] BP-15: Source scan for recursive `sync.Once.Do` — `panics.rs:132`
- [ ] BP-12: Unbuffered channel send from multiple goroutines — **reserved** (needs taint)
- [ ] BP-14: Goroutine without ctx.Done select — **reserved** (needs taint)

### 2.4 Fact extraction

- [x] `SourceIndex` with 12 precomputed `NEEDLES` — `source_index.rs`
- [x] Single-pass `build(source: &str)` at detector `run()` entry
- [x] `has(needle)` for fast pre-filtering before per-rule AST walk
- [x] Mirrors the CWE/PERF `SourceIndex` pattern

---

## Phase 3: Integration Planning (MVP COMPLETED)

### 3.1 Language plugin

- [x] Registered in `src/lang/go/detectors/mod.rs::all()`:
  ```rust
  Box::new(bad_practices::GoBadPracticeScan),
  ```

### 3.2 Ruleset integration

- [x] Rule descriptions as inline `RuleMetadata` constants in `metadata.rs`
- [ ] `ruleset/golang/bad-practices.json` — **not created** (no build.rs codegen)
- [x] `--list-rules` shows BP rules via existing `Rule::metadata()` path
- [x] `--explain BP-1` works via `metadata_for()` dispatch table

### 3.3 CLI integration

- [x] `--no-bp` flag disables entire category (`engine_config_cli_filters.rs:43`)
- [x] `--only BP-*` / `--skip BP-1` works via existing `--only`/`--skip` mechanism
- [x] `RuleCategory::BadPractice` filter in `cli/enums.rs:48`
- [x] `--bp-only` shorthand flag — **implemented** in `src/cli/args.rs:52-53` and wired in `src/cli/args_impl.rs:27`. (Plan was stale — code was ahead of docs.)

### 3.4 Configuration integration

- [x] `[bad_practices]` section in `slopguard.toml`:
  ```toml
  [bad_practices]
  enabled = true
  severity = "medium"
  ```
- [x] `BadPracticesConfig` struct in `engine/config/types.rs:102`
- [x] `slopguard.schema.json` updated with `bad_practices` block (`schema.json:104`)
- [x] `ScanContext.bad_practices_enabled` / `bad_practice_severity` fields

### 3.5 Reporting integration

- [x] `category_for_rule_id()` maps `BP-*` → `"bad_practice"` (`category.rs:2`)
- [x] JSON reporter includes `"category": "bad_practice"` per finding
- [x] SARIF reporter maps BP rules to `security-severity: 5.0` with `properties.category`
- [x] Text reporter renders BP findings with existing formatting

### 3.6 Test fixtures

- [x] 26 test fixture files in `tests/fixtures/go/bad_practices/` (13 vulnerable + 13 safe pairs — one per MVP rule)
- [ ] **No dedicated `tests/go_bad_practice_integration.rs`** yet (BP tests share generic config-filter tests)
- [x] Integration tests in `tests/engine_config_cli_filters.rs`, `tests/engine_config_parsing.rs`, `tests/reporting_json_finding.rs`, `tests/reporting_sarif_structured.rs`

---

## Phase 4: Prioritization (DEFERRED)

### 4.1 Ranking not done

- [ ] Score remaining candidates (Testing, API Design, Code Org, Production Hardening, Dependency Hygiene)
- [ ] Document prioritization matrix

### 4.2 Phased roadmap (unchanged from original plan)

| Phase | Scope | Effort | Status |
|---|---|---|---|
| **MVP** | BP-1..BP-15 (13 rules) | 1 week | ✅ **DONE** |
| **Phase 2 (P2.5-B)** | BP-16..BP-25 (Testing) | 1 week | ❌ Not started |
| **Phase 3 (P2.5-C)** | BP-26..BP-45 (API Design + Code Org) | 2 weeks | ❌ Not started |
| **Phase 4 (P2.5-D)** | BP-46..BP-65 (Prod Hardening + Dep Hygiene) | 2 weeks | ❌ Not started |

---

## Current Implementation (v2.0.0)

### File layout

```
src/lang/go/detectors/bad_practices/
├── mod.rs              # GoBadPracticeScan detector struct + Detector impl
├── dispatch.rs         # Rule dispatch table (BAD_PRACTICE_RULES) + RULE_IDS
├── metadata.rs         # RuleMetadata constants (BP_1_META .. BP_15_META, SCAN_METADATA)
├── source_index.rs     # SourceIndex with 12 NEEDLES for fast pre-filtering
└── rules/
    ├── mod.rs          # Re-exports
    ├── helpers.rs      # push_at(), line_start_byte() utilities
    ├── error_handling.rs  # BP-1, BP-2, BP-4, BP-5
    ├── sync.rs            # BP-6, BP-7, BP-8, BP-9
    ├── loops.rs           # BP-10, BP-11
    └── panics.rs          # BP-3, BP-13, BP-15
```

### Architecture notes

- **No `ruleset/golang/bad-practices.json`** — metadata is defined inline in `metadata.rs` rather than generated by `build.rs`. This differs from the CWE/PERF pattern but keeps BP rules self-contained.
- **No `BadPracticeCategory` enum** — `category_for_rule_id()` uses string-prefix matching instead. If the Testing/API Design phases are implemented, an enum may become warranted.
- **No `--bp-only` shorthand** — use `--only BP-*` or `--category bad_practices` instead.

---

## Remaining Work

### P1 — Complete MVP hygiene

- [ ] Override `Detector::kind() → FactDriven` on `GoBadPracticeScan` (currently defaults to `Heuristic`)
- [ ] Wire `check_no_prod_expect.sh` (3 `expect` calls still exist in walker/registry)
- [ ] Add dedicated `tests/go_bad_practice_integration.rs` with fixture-driven tests (currently uses generic config filter tests)

### P2 — Phase 2: Testing anti-patterns (BP-16..BP-25)

- [ ] Define 10 testing anti-pattern rules
- [ ] Detect only in `*_test.go` files
- [ ] Topics (from original plan): `time.Sleep` in tests, `t.Error`+`t.Fatal` redundancy, missing `t.Run()`, TestMain without `os.Exit`
- [ ] Implementation estimate: 1 week

### P3 — Phase 3: API Design + Code Organization (BP-26..BP-45)

- [ ] 20 rules across API Design and Code Org
- [ ] Needs: tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`
- [ ] Topics: interface size, exported interface without impl, `init()` side effects, package-level mutable globals
- [ ] Implementation estimate: 2 weeks

### P4 — Phase 4: Production Hardening + Dependency Hygiene (BP-46..BP-65)

- [ ] 20 rules across Production Hardening and Dependency Hygiene
- [ ] Needs: `go.mod` parsing, HTTP server config analysis, call-graph for graceful shutdown
- [ ] Topics: missing timeouts, no graceful shutdown, deprecated `ioutil`, old Go version
- [ ] Implementation estimate: 2 weeks

### Reserve — BP-12, BP-14 (goroutine leak detection)

- [ ] Taint-driven; depends on P2.1 taint infrastructure
- [ ] Not yet scoped

---

## Dependencies

- Existing detector architecture (`src/core/detector.rs`, `src/lang/go/detectors/cwe/mod.rs`)
- `SourceIndex` fact pattern (shared across CWE, PERF, BP)
- CLI: `--only`/`--skip` filtering already works for BP rules
- Config: `[bad_practices]` section already parsed in `slopguard.toml`
- Reporting: JSON/SARIF/text already support `"category": "bad_practice"`

---

## Verification

```bash
cargo test --all-features
# 268+ passed, 1 ignored (perf_regression budget)

cargo clippy --all-targets --all-features --locked -- -D warnings
# pass
```
