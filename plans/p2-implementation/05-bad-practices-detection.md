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


## Phase 4: Expanded Implementation Plan (Phased Roadmap)

### Phased roadmap

| Phase | Scope | Rules | Effort | Status |
|---|---|---|---|---|
| **MVP** | BP-1..BP-15 (13 rules) | 13 | 1 week | ✅ **DONE** |
| **Phase 1 — Hygiene** | Integration tests, BP-15 regression | 4 items | 2-3 days | ⏳ **In progress** |
| **Phase 2 — Metadata Refactor** | BadPracticeCategory enum, JSON, codegen | 4 items | 2-3 days | ❌ Not started |
| **Phase 3 (P2.5-B)** | Testing anti-patterns | BP-16..BP-25 (10 rules) | 1 week | ❌ Not started |
| **Phase 4 (P2.5-C)** | API Design + Code Organization | BP-26..BP-45 (20 rules) | 2 weeks | ❌ Not started |
| **Phase 5 (P2.5-D)** | Production Hardening + Dep Hygiene | BP-46..BP-65 (20 rules) | 2 weeks | ❌ Not started |
| **Reserve** | Goroutine leak detection (taint) | BP-12, BP-14 | -- | ⏳ Pending P2.1 |

---

## Phase 4.1: MVP Hygiene (2-3 days)

### 4.1.1 Dedicated integration test file

- [ ] Create `tests/go_bad_practice_integration.rs` with fixture-driven tests mirroring `tests/go_perf_detector_integration.rs`
  - For each BP fixture: materialize vulnerable → assert BP-N fires, materialize safe → assert no finding
- [ ] Create `tests/helpers/go_bp_cases.rs` helper for fixture discovery
- [ ] Remove BP-specific checks from generic tests (`tests/engine_config_cli_filters.rs`, `tests/reporting_json_finding.rs`)

### 4.1.2 BP-15 regression test

- [ ] Add fixture where recursive `sync.Once.Do()` is in a separate function (not just direct closure) — the harder case requiring call-chain walking

---

## Phase 4.2: Metadata Refactor — Match CWE/PERF Pattern (2-3 days)

### 4.2.1 Create BadPracticeCategory enum

- [ ] Add `BadPracticeCategory` enum in `src/rules/bp_category.rs`:
  ```rust
  pub enum BadPracticeCategory {
      ErrorHandling, Concurrency, Panics, Testing,
      ApiDesign, CodeOrganization, ProductionHardening, DependencyHygiene,
  }
  ```
- [ ] Map each BP rule ID to its category
- [ ] Replace `category_for_rule_id()` string matching in `src/rules/category.rs` with the enum
- [ ] Ensure reporters continue to emit `"category": "bad_practice"` (enum is for internal dispatch)

### 4.2.2 Create ruleset/golang/bad-practices.json

- [ ] Create `ruleset/golang/bad-practices.json` with per-rule entries: `id`, `title`, `description`, `detection_notes`, `severity`, `category`
- [ ] Include all 13 MVP rules + placeholders for BP-16..BP-65

### 4.2.3 Codegen from bad-practices.json

- [ ] Add `gen_bp.rs` in `build/` that generates `META_BP_N` constants from the JSON
- [ ] Update `build.rs` to invoke BP codegen
- [ ] Replace inline constants in `metadata.rs` with `include!` of generated code

### 4.2.4 Verify --list-rules and --explain for BP

- [ ] `--list-rules` shows BP rules with proper category grouping
- [ ] `--explain BP-1` pulls from generated metadata
- [ ] Remove inline `metadata_for()` dispatch table if redundant

---

## Phase 4.3: Testing Anti-Patterns — BP-16..BP-25 (1 week)

> All rules fire only in `*_test.go` files.

### 4.3.1 Rule definitions

- [ ] **BP-16**: `time.Sleep` in test (not in retry loop) — AST walk for `time.Sleep()` in `*_test.go` outside for/range
- [ ] **BP-17**: `t.Error` followed by `t.Fatal` (redundant) — line scan for consecutive calls
- [ ] **BP-18**: `t.Error`/`t.Errorf` without `t.FailNow`/`return` — AST check within same block
- [ ] **BP-19**: Missing `t.Helper()` on test helper functions — function called from test without `t.Helper()` as first statement
- [ ] **BP-20**: Table-driven test without `t.Run` — detect monolithic for vs `for _, tc := range tests { t.Run(...) }`
- [ ] **BP-21**: `t.Parallel()` missing in table-driven subtest — detect `t.Run` body without `t.Parallel()`
- [ ] **BP-22**: TestMain without `os.Exit` — AST scan for `func TestMain(m *testing.M)` body missing `os.Exit`
- [ ] **BP-23**: `testing.Short()` not checked — heuristic: `t.Run` body > 20 lines with no guard
- [ ] **BP-24**: Test file without test functions — `*_test.go` with zero `func Test*` declarations
- [ ] **BP-25**: Test helper returns error instead of `t.Fatal` — helper returns `error` but always checks `t.Fatal`

### 4.3.2 Detection approach

- [ ] Add BP-16..BP-25 detection functions to a new `rules/testing.rs`
- [ ] Use `unit.path.ends_with("_test.go")` for file-name pre-filter
- [ ] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`
- [ ] Add metadata constants for BP-16..BP-25

### 4.3.3 Test fixtures

- [ ] Create 20 fixture files (10 vulnerable + 10 safe) in `tests/fixtures/go/bad_practices/`
- [ ] Vulnerable fixtures use `_test.go` suffix
- [ ] Register in `tests/fixtures/manifest.toml`
- [ ] Verify via `tests/go_bad_practice_integration.rs`

---

## Phase 4.4: API Design + Code Organization — BP-26..BP-45 (2 weeks)

> Requires tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`.

### 4.4.1 API Design (BP-26..BP-35)

- [ ] **BP-26**: Context not first parameter — AST check `ctx context.Context` is first param
- [ ] **BP-27**: Exported function returns unexported type — `func FuncName(...)` returns lowercase type
- [ ] **BP-28**: Interface with single method — should be function type instead
- [ ] **BP-29**: Interface bloat (>5 methods)
- [ ] **BP-30**: Exported interface without documented implementation in same package
- [ ] **BP-31**: Function returns concrete type instead of interface (heuristic)
- [ ] **BP-32**: Error type as `string` instead of `struct` — `type X string` with `func (x X) Error() string`
- [ ] **BP-33**: Sentinel error without `Is` method
- [ ] **BP-34**: Error wrapping without `%w` — `fmt.Errorf("msg: %v", err)` vs `%w`
- [ ] **BP-35**: Package name != directory name

### 4.4.2 Code Organization (BP-36..BP-45)

- [ ] **BP-36**: `init()` with side effects — AST walk for non-variable statements in `init()`
- [ ] **BP-37**: Package-level mutable global variable — `var x = ...` at package level, not in tests
- [ ] **BP-38**: Unexported helper with no internal callers in same package
- [ ] **BP-39**: Exported function without doc comment
- [ ] **BP-40**: Package-level block with unrelated constants (heuristic: name prefixes differ)
- [ ] **BP-41**: File header missing package doc comment
- [ ] **BP-42**: Import alias not used consistently — alias appears only once
- [ ] **BP-43**: Dot import outside test files
- [ ] **BP-44**: Blank import without justification (not driver/image pattern)
- [ ] **BP-45**: Receiver name inconsistent across methods — `(t *T)` vs `(this *T)` on same type

### 4.4.3 Detection approach

- [ ] Create `rules/api_design.rs` (BP-26..BP-35) and `rules/code_organization.rs` (BP-36..BP-45)
- [ ] Use tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`, `var_declaration`
- [ ] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`

### 4.4.4 Test fixtures

- [ ] Create 40 fixture files (20 vulnerable + 20 safe) in `tests/fixtures/go/bad_practices/`
- [ ] Register in `tests/fixtures/manifest.toml`

---

## Phase 4.5: Production Hardening + Dependency Hygiene — BP-46..BP-65 (2 weeks)

> Co-developed with P2.1 taint for some rules. BP-56..BP-65 need go.mod parsing.

### 4.5.1 Production Hardening (BP-46..BP-55)

- [ ] **BP-46**: HTTP server without `ReadTimeout`/`WriteTimeout`
- [ ] **BP-47**: No graceful shutdown (`Shutdown` not called)
- [ ] **BP-48**: `log.Fatal`/`os.Exit` in non-main function
- [ ] **BP-49**: Deferred function without error handling
- [ ] **BP-50**: No signal handling for SIGTERM/SIGINT in long-running process
- [ ] **BP-51**: Panic recovery without re-panic in library code
- [ ] **BP-52**: Integer overflow in arithmetic (heuristic: multiplication without bounds check)
- [ ] **BP-53**: `encoding/gob` registered types not matching
- [ ] **BP-54**: No rate limiting on public HTTP endpoint
- [ ] **BP-55**: Missing RequestID propagation in middleware chain

### 4.5.2 Dependency Hygiene (BP-56..BP-65)

- [ ] **BP-56**: Deprecated stdlib package used (ioutil, golang.org/x/net/context)
- [ ] **BP-57**: Old Go version in go.mod (>2 minor versions behind latest)
- [ ] **BP-58**: Unpinned dependency version (v1.x instead of v1.2.3)
- [ ] **BP-59**: Direct dependency not used in any import — project-level scan
- [ ] **BP-60**: Test dependency in main go.mod
- [ ] **BP-61**: Indirect dependency not listed in go.mod (missing `// indirect`)
- [ ] **BP-62**: Dependency used only in one file, could be internalized
- [ ] **BP-63**: Dependency with known CVE not updated
- [ ] **BP-64**: Replace directive pointing to local filesystem
- [ ] **BP-65**: go.sum missing entries

### 4.5.3 Detection approach

- [ ] Create `rules/production_hardening.rs` and `rules/dependency_hygiene.rs`
- [ ] BP-56..BP-65 need go.mod parsing — integrate with `src/engine/dependencies/` infrastructure
- [ ] BP-57, BP-58, BP-61, BP-64, BP-65 are project-level scans
- [ ] Register per-file rules in `BAD_PRACTICE_RULES`; add project-level BP detector for project-wide rules

### 4.5.4 Test fixtures

- [ ] Per-file rules: create fixture files in `tests/fixtures/go/bad_practices/`
- [ ] Project-level rules: create fixture directories with go.mod + .go files
- [ ] Register in `tests/fixtures/manifest.toml`

---

## Phase 4.6: Documentation

- [ ] Create `docs/bad-practices.md` — one paragraph per BP rule with rationale and canonical fix

---

## Reserved — BP-12, BP-14 (Goroutine Leak Detection)

> Taint-driven; depends on P2.1 Phase F (inter-procedural taint).

- [ ] **BP-12**: Unbuffered channel send from multiple goroutines without adequate receivers
- [ ] **BP-14**: Goroutine without `ctx.Done` select

These ship with P2.1 Phase 2 (inter-procedural taint), tracked in `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md`.

---

## Quick Reference

| Workstream | Items | Rules | Effort | Priority | Status |
|---|---|---|---|---|---|
| MVP | Architecture + 13 rules | BP-1..BP-15 | 1w | P0 | ✅ |
| Phase 1 — Hygiene | Integration tests, BP-15 regression | 4 items | 2-3d | P1 | ⏳ |
| Phase 2 — Metadata refactor | Category enum, JSON, codegen | 4 items | 2-3d | P2 | ❌ |
| Phase 3 — Testing | Test anti-patterns | BP-16..BP-25 (10) | 1w | P3 | ❌ |
| Phase 4 — API + Code Org | API design + code structure | BP-26..BP-45 (20) | 2w | P4 | ❌ |
| Phase 5 — Prod + Dep | Production hardening + deps | BP-46..BP-65 (20) | 2w | P5 | ❌ |
| Documentation | docs/bad-practices.md | 1 doc | 1d | P5 | ❌ |
| Reserved | Goroutine leak (taint) | BP-12, BP-14 | -- | -- | ⏳ |

---

## Dependencies

- Existing detector architecture (`src/core/detector.rs`, `src/lang/go/detectors/cwe/mod.rs`) — ✅ ready
- `SourceIndex` fact pattern (shared across CWE, PERF, BP) — ✅ ready
- CLI: `--only`/`--skip` filtering already works for BP rules — ✅ ready
- Config: `[bad_practices]` section already parsed in `slopguard.toml` — ✅ ready
- Reporting: JSON/SARIF/text already support `"category": "bad_practice"` — ✅ ready
- Tree-sitter queries (Phase 4.4): `interface_type`, `type_spec`, `method_declaration`
- go.mod parsing (Phase 4.5): `src/engine/dependencies/` infrastructure
- Taint tracking (BP-12, BP-14): P2.1 Phase F

---

## Verification

```bash
cargo test --all-features
# 268+ passed, 1 ignored (perf_regression budget)

cargo clippy --all-targets --all-features --locked -- -D warnings
# pass
```
