# P2.5 — Bad Practices Detection (Implementation Status)

> **Parent:** `plans/p2.md` — P2.5
> **Status:** ✅ **All planned BP phases implemented.** BP-1..BP-65 now have shipped detector coverage, fixture coverage, and documentation, including bounded heuristic implementations for the formerly reserved BP-12 and BP-14 rules.
> **Estimated effort:** MVP was ~1 week. Follow-on phases are now complete.
> **See also:** `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md` (original scoping doc), `plans/v2.0.0/rust-remediation-phase-3.md` (remediation tracking)
> **Pending work breakdown:** `plans/v2.0.0/pending-work/03-bad-practices-remaining.md`

---

## Overview

Bad Practices detection is a new rule category beyond CWE (security) and PERF (performance), covering general Go software engineering anti-patterns. The MVP (BP-1..BP-15) was implemented as part of the v2.0.0 remediation. This plan tracks what's built and what remains.

---

## Executive Summary

- **13 rules implemented** across 4 domain modules: `error_handling`, `sync`, `loops`, `panics`.
- **Architecture:** Single `GoBadPracticeScan` detector (Option A) with a `SourceIndex` fact pre-filter and per-rule dispatch table — mirrors the CWE/PERF pattern.
- **Metadata refactor landed:** BP metadata now comes from `ruleset/golang/bad-practices.json`, `build.rs` generates `go_bp_metadata.rs`, and `BadPracticeCategory` owns BP sub-category mapping before reporters collapse back to `"bad_practice"`.
- **Hygiene landed:** Dedicated BP integration coverage now exercises fixture scans, CLI scans, config/reporting hooks, and an indirect `BP-15` regression.
- **Testing heuristics landed:** `BP-16..BP-25` now have detector implementations in `rules/testing.rs`, fixture coverage, and CLI/manifest validation that explicitly scans `_test.go` materializations.
- **Phase 4.4 landed:** `rules/api_design.rs` and `rules/code_organization.rs` now cover all BP-26..BP-45 rules, including package-aware heuristics for BP-30, BP-31, and BP-41 plus nested-path fixture materialization for path-sensitive cases.
- **Phase 4.5 landed:** `rules/production_hardening.rs` and `rules/dependency_hygiene.rs` now cover BP-46..BP-65, including bounded heuristics for gob registration mismatches, missing indirect annotations, and curated vulnerable-module checks.
- **Concurrency reserve closed:** BP-12 and BP-14 now ship as bounded heuristics in `rules/sync.rs`, with the taint engine remaining an optional future precision upgrade rather than a blocker.
- **Documentation landed:** `documents/bad-practices.md` now records rationale and canonical fixes for every shipped BP rule.

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
- [x] **Concurrency** — BP-6..BP-15 (implemented, including BP-12/BP-14)
- [x] **Testing** — BP-16..BP-25 (implemented in Phase 4.3)
- [x] **API Design** — BP-26..BP-35 (implemented in Phase 4.4)
- [x] **Code Organization** — BP-36..BP-45 (implemented in Phase 4.4)
- [x] **Production Hardening** — BP-46..BP-55 implemented
- [x] **Dependency Hygiene** — BP-56..BP-65 implemented

### 1.3 Scope criteria applied

- [x] Statically detectable (AST/pattern-based)
- [x] Not already covered by CWE/PERF rules
- [x] Not already covered by `go vet` / `staticcheck` defaults
- [x] High-signal, low-noise
- [x] Out-of-scope documented (stylistic, language-level vet checks, runtime patterns)

### 1.4 Rule ID scheme selected

- [x] Prefix: `BP-N` (Bad Practice)
- [x] Sequential numbering within each sub-category block
- [x] Implemented: BP-1..BP-15

---

## Phase 2: Detection Strategy (MVP IMPLEMENTED)

### 2.1 Detector architecture

- [x] **Option A chosen** — single `GoBadPracticeScan` detector with domain submodules
- [x] Located at `src/lang/go/detectors/bad_practices/mod.rs:13`

### 2.2 Rule metadata

- [x] Generated `RuleMetadata` constants now come from `src/lang/go/detectors/bad_practices/metadata.rs` via `include!(concat!(env!("OUT_DIR"), "/go_bp_metadata.rs"))`
- [x] `ruleset/golang/bad-practices.json` exists with implemented rules plus planned placeholders
- [x] `build.rs` invokes BP metadata codegen through `build/gen_bp.rs`

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
- [x] BP-12: Line-scan heuristic for unbuffered channel sends from multiple goroutines without visible coordinated receivers — `sync.rs`
- [x] BP-14: Line-scan heuristic for long-running goroutines that ignore `ctx.Done()` — `sync.rs`
- [x] BP-15: AST-assisted same-file call-chain walk for recursive `sync.Once.Do` — `panics.rs:134`

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
- [x] `ruleset/golang/bad-practices.json` feeds generated BP metadata
- [x] `--list-rules` shows BP rules via existing `Rule::metadata()` path
- [x] `--explain BP-1` works via generated BP metadata lookup

### 3.3 CLI integration

- [x] `--no-bp` flag disables entire category (`tests/go_bad_practice_integration.rs`)
- [x] `--only BP-*` / `--skip BP-1` works via existing `--only`/`--skip` mechanism
- [x] `RuleCategory::BadPractice` filter in `cli/enums.rs:48`
- [x] `--bp-only` shorthand flag — **implemented** in `src/cli/args.rs:52-53` and wired in `src/cli/args_impl.rs:27`. (Plan was stale — code was ahead of docs.)

### 3.4 Configuration integration

- [x] `[bad_practices]` section in `codehound.toml`:
  ```toml
  [bad_practices]
  enabled = true
  severity = "medium"
  ```
- [x] `BadPracticesConfig` struct in `engine/config/types.rs:102`
- [x] `codehound.schema.json` updated with `bad_practices` block (`schema.json:104`)
- [x] `ScanContext.bad_practices_enabled` / `bad_practice_severity` fields

### 3.5 Reporting integration

- [x] `BadPracticeCategory` maps `BP-*` ids to sub-categories and `category_for_rule_id()` still emits `"bad_practice"` for reporters
- [x] JSON reporter includes `"category": "bad_practice"` per finding
- [x] SARIF reporter maps BP rules to `security-severity: 5.0` with `properties.category`
- [x] Text reporter renders BP findings with existing formatting

### 3.6 Test fixtures

- [x] 28 test fixture files in `tests/fixtures/go/bad_practices/` (14 vulnerable + 14 safe pairs, including indirect `BP-15`)
- [x] Dedicated `tests/go_bad_practice_integration.rs` covers fixture scans, CLI scans, config filters, JSON reporting, and SARIF reporting
- [x] Supporting helper `tests/helpers/go_bp_cases.rs` keeps BP fixture discovery in sync with the directory
- [x] Remaining generic coverage still lives in `tests/engine_config_parsing.rs`, `tests/reporting_json_finding.rs`, and `tests/reporting_sarif_core.rs`

---


## Phase 4: Expanded Implementation Plan (Phased Roadmap)

### Phased roadmap

| Phase | Scope | Rules | Effort | Status |
|---|---|---|---|---|
| **MVP** | BP-1..BP-15 (13 rules) | 13 | 1 week | ✅ **DONE** |
| **Phase 1 — Hygiene** | Integration tests, BP-15 regression | 4 items | 2-3 days | ✅ **DONE** |
| **Phase 2 — Metadata Refactor** | BadPracticeCategory enum, JSON, codegen | 4 items | 2-3 days | ✅ **DONE** |
| **Phase 3 (P2.5-B)** | Testing anti-patterns | BP-16..BP-25 (10 rules) | 1 week | ✅ **DONE** |
| **Phase 4 (P2.5-C)** | API Design + Code Organization | BP-26..BP-45 (20 rules) | 2 weeks | ✅ **DONE** |
| **Phase 5 (P2.5-D)** | Production Hardening + Dep Hygiene | BP-46..BP-65 (20 rules) | 2 weeks | ✅ **DONE** |
| **Concurrency Reserve Closure** | Former taint-reserved heuristics | BP-12, BP-14 | -- | ✅ **DONE** |

---

## Phase 4.1: MVP Hygiene (2-3 days)

### 4.1.1 Dedicated integration test file

- [x] Create `tests/go_bad_practice_integration.rs` with fixture-driven tests mirroring `tests/go_perf_detector_integration.rs`
  - For each BP fixture: materialize vulnerable → assert BP-N fires, materialize safe → assert no finding
- [x] Create `tests/helpers/go_bp_cases.rs` helper for fixture discovery
- [x] Remove BP-specific checks from generic tests (`tests/engine_config_cli_filters.rs`, `tests/reporting_json_finding.rs`)

### 4.1.2 BP-15 regression test

- [x] Add fixture where recursive `sync.Once.Do()` is in a separate function (not just direct closure) — the harder case requiring call-chain walking

---

## Phase 4.2: Metadata Refactor — Match CWE/PERF Pattern (2-3 days)

### 4.2.1 Create BadPracticeCategory enum

- [x] Add `BadPracticeCategory` enum in `src/rules/bp_category.rs`:
  ```rust
  pub enum BadPracticeCategory {
      ErrorHandling, Concurrency, Panics, Testing,
      ApiDesign, CodeOrganization, ProductionHardening, DependencyHygiene,
  }
  ```
- [x] Map each BP rule ID to its category
- [x] Replace `category_for_rule_id()` string matching in `src/rules/category.rs` with the enum
- [x] Ensure reporters continue to emit `"category": "bad_practice"` (enum is for internal dispatch)

### 4.2.2 Create ruleset/golang/bad-practices.json

- [x] Create `ruleset/golang/bad-practices.json` with per-rule entries: `id`, `title`, `description`, `detection_notes`, `severity`, `category`
- [x] Include all 13 MVP rules + placeholders for BP-16..BP-65

### 4.2.3 Codegen from bad-practices.json

- [x] Add `gen_bp.rs` in `build/` that generates `META_BP_N` constants from the JSON
- [x] Update `build.rs` to invoke BP codegen
- [x] Replace inline constants in `metadata.rs` with `include!` of generated code

### 4.2.4 Verify --list-rules and --explain for BP

- [x] `--list-rules` shows BP rules with proper category grouping
- [x] `--explain BP-1` pulls from generated metadata
- [x] Remove inline `metadata_for()` dispatch table if redundant

---

## Phase 4.3: Testing Anti-Patterns — BP-16..BP-25 (1 week)

> All rules fire only in `*_test.go` files.

### 4.3.1 Rule definitions

- [x] **BP-16**: `time.Sleep` in test (not in retry loop) — `time.Sleep()` in `*_test.go` outside loop ancestry
- [x] **BP-17**: `t.Error` followed by `t.Fatal` (redundant) — consecutive-line test failure escalation
- [x] **BP-18**: `t.Error`/`t.Errorf` without `t.FailNow`/`return` — line-based continuation check
- [x] **BP-19**: Missing `t.Helper()` on test helper functions — helper body first non-empty line must be `t.Helper()`
- [x] **BP-20**: Table-driven test without `t.Run` — loop in `Test*` body without `t.Run`
- [x] **BP-21**: `t.Parallel()` missing in table-driven subtest — `t.Run` closure inside loop without `t.Parallel()`
- [x] **BP-22**: TestMain without `os.Exit` — `func TestMain(m *testing.M)` body missing `os.Exit`
- [x] **BP-23**: `testing.Short()` not checked — long `Test*` body without `testing.Short()`
- [x] **BP-24**: Test file without test functions — `*_test.go` with zero `func Test*` declarations
- [x] **BP-25**: Test helper returns error instead of `t.Fatal` — helper with `*testing.T` parameter and `error` result

### 4.3.2 Detection approach

- [x] Add BP-16..BP-25 detection functions to `rules/testing.rs`
- [x] Use `unit.display_path.ends_with("_test.go")` for file-name pre-filter
- [x] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`
- [x] Generated metadata constants cover BP-16..BP-25 from `bad-practices.json`

### 4.3.3 Test fixtures

- [x] Create 20 fixture files (10 vulnerable + 10 safe) in `tests/fixtures/go/bad_practices/`
- [x] Vulnerable fixtures use `_test.go` suffix
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify via `tests/go_bad_practice_integration.rs` and `tests/fixture_manifest_integration_manifest.rs`

---

## Phase 4.4: API Design + Code Organization — BP-26..BP-45 (2 weeks)

> Requires tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`.

### 4.4.1 API Design (BP-26..BP-35)

- [x] **BP-26**: Context not first parameter — exported function/method params containing `context.Context` now require it to be first
- [x] **BP-27**: Exported function returns unexported type — exported APIs returning lowercase local result types now flag
- [x] **BP-28**: Interface with single method — single-method `interface` declarations now flag
- [x] **BP-29**: Interface bloat (>5 methods) — multi-line interfaces above the threshold now flag
- [x] **BP-30**: Exported interface without documented implementation in same package — same-package implementation scan now flags exported interfaces with no local concrete implementer
- [x] **BP-31**: Function returns concrete type instead of interface (heuristic) — exported constructors returning local concrete types now flag when the package already exposes a matching interface
- [x] **BP-32**: Error type as `string` instead of `struct` — `type X string` + `Error() string` now flags
- [x] **BP-33**: Sentinel error without `Is` method — sentinel-style custom error vars now require `Is(error) bool`
- [x] **BP-34**: Error wrapping without `%w` — `fmt.Errorf(..., err)` using `%v`/`%s` now flags
- [x] **BP-35**: Package name != directory name — path-sensitive package-vs-directory mismatch now flags, with flat fixture materializations excluded

### 4.4.2 Code Organization (BP-36..BP-45)

- [x] **BP-36**: `init()` with side effects — `init()` bodies containing calls / goroutines / defers now flag
- [x] **BP-37**: Package-level mutable global variable — top-level `var` declarations now flag, excluding sentinel `Err*` globals
- [x] **BP-38**: Unexported helper with no internal callers in same package — helper-like private functions with zero same-file callers now flag
- [x] **BP-39**: Exported function without doc comment — exported functions and methods on exported receiver types now require doc comments
- [x] **BP-40**: Package-level block with unrelated constants (heuristic: name prefixes differ)
- [x] **BP-41**: File header missing package doc comment — package anchor files now require a `// Package <name>` doc comment somewhere in the same package
- [x] **BP-42**: Import alias not used consistently — alias appears only once
- [x] **BP-43**: Dot import outside test files
- [x] **BP-44**: Blank import without justification (not driver/image pattern)
- [x] **BP-45**: Receiver name inconsistent across methods — `(t *T)` vs `(this *T)` on same type

### 4.4.3 Detection approach

- [x] Created `rules/api_design.rs` (BP-26..BP-35) and `rules/code_organization.rs` (BP-36..BP-45)
- [x] Registered implemented rules in `BAD_PRACTICE_RULES` in `dispatch.rs`
- [x] Extended fixture materialization to support nested output paths so directory-sensitive BP fixtures can be expressed in `.txt` form
- [x] Added bounded package-aware scans for BP-30, BP-31, and BP-41 by reading same-directory package files without promoting the whole detector to a global package-analysis pass

### 4.4.4 Test fixtures

- [x] Created 40 fixture files (20 vulnerable + 20 safe) in `tests/fixtures/go/bad_practices/` for BP-26..BP-45
- [x] Registered the new fixtures in `tests/fixtures/manifest.toml`
- [x] Added dedicated nested-path fixtures for BP-30, BP-31, and BP-41 so package-aware heuristics can be exercised without cross-fixture contamination

---

## Phase 4.5: Production Hardening + Dependency Hygiene — BP-46..BP-65 (2 weeks)

> Co-developed with P2.1 taint for some rules. A bounded Phase 4.5 slice is now implemented; remaining rules still need deeper semantic or ecosystem-aware analysis.

### 4.5.1 Production Hardening (BP-46..BP-55)

- [x] **BP-46**: HTTP server without `ReadTimeout`/`WriteTimeout` — `http.Server` literals now require both timeout fields
- [x] **BP-47**: No graceful shutdown (`Shutdown` not called) — project-root scan now flags server-style binaries that never call `Shutdown`
- [x] **BP-48**: `log.Fatal`/`os.Exit` in non-main function — non-main code paths now flag process-terminating exits
- [x] **BP-49**: Deferred function without error handling — deferred `.Close()`, `.Flush()`, and `.Sync()` calls now require explicit error handling
- [x] **BP-50**: No signal handling for SIGTERM/SIGINT in long-running process — project-root scan now requires `os/signal` handling for long-running servers
- [x] **BP-51**: Panic recovery without re-panic in library code — recover blocks in non-main code now flag unless they clearly log/escalate
- [x] **BP-52**: Integer overflow in arithmetic (heuristic: multiplication without bounds check) — `make(...)` allocation multiplications now require an obvious overflow guard marker
- [x] **BP-53**: `encoding/gob` registered types not matching — nearby `gob.Register` and `Encode`/`Decode` payloads must line up on the same local type
- [x] **BP-54**: No rate limiting on public HTTP endpoint — project-root server scans now require a visible rate-limiter marker on public handlers
- [x] **BP-55**: Missing RequestID propagation in middleware chain — project-root request-path logging scans now require visible request-id propagation markers

### 4.5.2 Dependency Hygiene (BP-56..BP-65)

- [x] **BP-56**: Deprecated stdlib package used (ioutil, golang.org/x/net/context)
- [x] **BP-57**: Old Go version in go.mod (>2 minor versions behind latest) — project-level `go.mod` scans now flag majors outside the current two-release support window
- [x] **BP-58**: Unpinned dependency version (v1.x instead of v1.2.3) — project-level `go.mod` scan now flags major/minor-only pins
- [x] **BP-59**: Direct dependency not used in any import — project-level import reconciliation now flags unused direct requirements
- [x] **BP-60**: Test dependency in main go.mod — project-level scan now flags requirements imported only from `_test.go`
- [x] **BP-61**: Indirect dependency not listed in go.mod (missing `// indirect`) — non-imported requirements now require an explicit `// indirect` marker
- [x] **BP-62**: Dependency used only in one file, could be internalized — multi-file projects now flag direct dependencies imported from exactly one non-test file
- [x] **BP-63**: Dependency with known CVE not updated — project-level scans now compare requirements against the curated advisory snapshot in `ruleset/golang/go_module_advisories.csv`
- [x] **BP-64**: Replace directive pointing to local filesystem — local path `replace` directives now flag
- [x] **BP-65**: go.sum missing entries — missing or empty `go.sum` now flags

### 4.5.3 Detection approach

- [x] Created `rules/production_hardening.rs` and `rules/dependency_hygiene.rs`
- [x] Added bounded `go.mod` / `go.sum` parsing heuristics for BP-56..BP-65, including indirect-annotation checks and curated vulnerable-version matching
- [x] Implemented project-level anchor scans for BP-47, BP-50, BP-54, BP-55, BP-57, BP-58, BP-59, BP-60, BP-61, BP-62, BP-63, BP-64, and BP-65, with materialized text fixtures explicitly excluded to avoid repo-root bleed-through
- [x] Registered shipped per-file rules in `BAD_PRACTICE_RULES` and added dedicated project-fixture integration coverage for project-wide rules

### 4.5.4 Test fixtures

- [x] Added per-file fixture files in `tests/fixtures/go/bad_practices/` for BP-12, BP-14, BP-46, BP-48, BP-49, BP-51, BP-52, BP-53, and BP-56
- [x] Added project-level fixture directories in `tests/fixtures/go/bad_practices_projects/` for BP-47, BP-50, BP-54, BP-55, BP-57, BP-58, BP-59, BP-60, BP-61, BP-62, BP-63, BP-64, and BP-65
- [x] Registered the new per-file fixtures in `tests/fixtures/manifest.toml` and added `tests/go_bad_practice_project_integration.rs` for project-root cases

---

## Phase 4.6: Documentation

- [x] Created `documents/bad-practices.md` — one paragraph per BP rule with rationale and canonical fix

---

## Former Reserve — BP-12, BP-14

> The original plan reserved BP-12 and BP-14 for a future taint phase. The current implementation ships bounded heuristics in `rules/sync.rs`; future taint work can still improve precision, but it is no longer required for baseline detector coverage.

- [x] **BP-12**: Unbuffered channel send from multiple goroutines without adequate receivers
- [x] **BP-14**: Goroutine without `ctx.Done` select

---

## Quick Reference

| Workstream | Items | Rules | Effort | Priority | Status |
|---|---|---|---|---|---|
| MVP | Architecture + 13 rules | BP-1..BP-15 | 1w | P0 | ✅ |
| Phase 1 — Hygiene | Integration tests, BP-15 regression | 4 items | 2-3d | P1 | ✅ |
| Phase 2 — Metadata refactor | Category enum, JSON, codegen | 4 items | 2-3d | P2 | ✅ |
| Phase 3 — Testing | Test anti-patterns | BP-16..BP-25 (10) | 1w | P3 | ✅ |
| Phase 4 — API + Code Org | API design + code structure | BP-26..BP-45 (20) | 2w | P4 | ✅ |
| Phase 5 — Prod + Dep | Production hardening + deps | BP-46..BP-65 (20) | 2w | P5 | ✅ |
| Documentation | documents/bad-practices.md | 1 doc | 1d | P5 | ✅ |
| Former Reserve | Goroutine leak heuristics | BP-12, BP-14 | -- | -- | ✅ |

---

## Dependencies

- Existing detector architecture (`src/core/detector.rs`, `src/lang/go/detectors/cwe/mod.rs`) — ✅ ready
- `SourceIndex` fact pattern (shared across CWE, PERF, BP) — ✅ ready
- CLI: `--only`/`--skip` filtering already works for BP rules — ✅ ready
- Config: `[bad_practices]` section already parsed in `codehound.toml` — ✅ ready
- Reporting: JSON/SARIF/text already support `"category": "bad_practice"` — ✅ ready
- Tree-sitter queries (Phase 4.4): `interface_type`, `type_spec`, `method_declaration`
- go.mod parsing (Phase 4.5): `src/engine/dependencies/` infrastructure
- Taint tracking (BP-12, BP-14): P2.1 Phase F

---

## Verification

```bash
cargo test -q --test go_bad_practice_integration
cargo test -q --test go_bad_practice_project_integration --test fixture_manifest_integration_manifest
cargo test -q --test perf_regression
cargo test -q
```
