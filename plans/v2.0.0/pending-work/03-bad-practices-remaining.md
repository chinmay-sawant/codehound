# P2.5 — Bad Practices: Remaining Work (BP-16..BP-65 + Metadata Refactor + Hygiene)

> **Parent:** `plans/p2-implementation/05-bad-practices-detection.md` — P2.5
> **Status:** MVP shipped (BP-1..BP-11, BP-13, BP-15 = 13 rules). Phases 2–4 (Testing, API Design, Code Org, Production Hardening, Dependency Hygiene) **not started**.
> **Estimated effort:** ~6 weeks total
> **See also:** `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md`, `plans/v2.0.0/antipattern-remediation/rust-best-practices.md`

---

## Overview

Bad Practices (BP) detection is a rule category beyond CWE (security) and PERF (performance). The MVP implemented 13 rules across error handling, concurrency, loops, and panics. The remaining work spans:

1. **Metadata refactor**: add `BadPracticeCategory` enum, `ruleset/golang/bad-practices.json`, and `build.rs` codegen to match the CWE/PERF pattern
2. **Hygiene items**: fix `Detector::kind()`, add dedicated integration tests, add negative fixtures
3. **Phase 2**: BP-16..BP-25 — Testing anti-patterns (10 rules)
4. **Phase 3**: BP-26..BP-45 — API Design + Code Organization (20 rules)
5. **Phase 4**: BP-46..BP-65 — Production Hardening + Dependency Hygiene (20 rules)
6. **Reserved**: BP-12, BP-14 — goroutine leak detection (depends on P2.1 taint)

---

## Executive Summary

- **13 rules shipped** in MVP. 50 rules remain across 5 sub-categories.
- **2 rules reserved** (BP-12, BP-14) for taint-based implementation.
- **Detector architecture** is sound (single `GoBadPracticeScan` struct, function-pointer dispatch, `SourceIndex` pre-filter).
- **CLI integration is complete** (`--no-bp`, `--bp-only`, `[bad_practices]` config block, severity overrides in `ScanContext`).
- **Missing**: dedicated integration test file, `BadPracticeCategory` enum, `ruleset/golang/bad-practices.json`, negative fixtures, `documents/bad-practices.md`.

**Recommended order:** Hygiene (quick wins) → Metadata refactor (unlocks `--explain` for BP) → Phase 2 (Testing — high value, scoped to `*_test.go`) → Phase 3 (API Design + Code Org) → Phase 4 (Prod Hardening + Dep Hygiene — overlaps with PERF and taint).

---

## Phase 1 — MVP Hygiene

> **Status:** ⏳ Partially done. 3 items remaining.
> **Effort:** 2–3 days

### 1.1 Detector kind

- [~] ~~Override `Detector::kind()` on `GoBadPracticeScan` to return `FactDriven`~~ `(skipped: DetectorKind enum removed in ponytail audit — only Heuristic variant existed, `kind()` trait method no longer exists)`

### 1.2 Wire `check_no_prod_expect.sh`

- [x] Audit `src/lang/go/detectors/bad_practices/` for any `expect()` or `unwrap()` calls in production code — **0 found**, BP module is clean
- [x] Fix them to use proper error propagation — nothing to fix
- [x] Verify `scripts/check_no_prod_expect.sh` passes against the BP module — confirmed clean

### 1.3 Dedicated integration test file

- [x] Create `tests/go_bad_practice_integration.rs` with fixture-driven tests that mirror `tests/go_perf_detector_integration.rs`:
  ```rust
  #[test]
  fn bp_fixtures_fire_vulnerable_and_silence_safe() {
      // For each BP fixture:
      //   materialize vulnerable → assert finding for BP-N rule
      //   materialize safe → assert no findings for BP-N rule
  }
  ```
- [x] Create a `tests/helpers/go_bp_cases.rs` helper for fixture discovery (analogous to `tests/helpers/go_perf_cases.rs`)
- [x] Remove the BP-specific checks from generic tests (`tests/engine_config_cli_filters.rs`, `tests/reporting_json_finding.rs`) that currently serve as BP integration — make those config-filter tests generic only, and put BP-specific tests in the dedicated file

### 1.4 Negative fixtures

- [x] For each MVP rule (BP-1..BP-11, BP-13, BP-15), create a negative fixture that exercises the "almost but not quite" pattern:
  - BP-1: `_ = doSomething()` where `doSomething()` returns `void` (not `error`) — should not fire
  - BP-3: `panic()` in `init()` function — should fire (init is outside main/test)
  - BP-5: `defer file.Close()` — should not fire (deferred close is correct pattern)
  - BP-6: `wg.Add(1)` before `go func()` — should not fire
  - BP-10: `time.After()` outside loop — should not fire
  - BP-11: `defer` in straight-line code (not in loop) — should not fire
  - BP-13: `context.Background()` in `main()` — should not fire
  - BP-15: `sync.Once.Do()` with non-recursive closure — should not fire
- [x] Register in `tests/fixtures/manifest.toml` with `required_rules = []`

### 1.5 BP-15 regression test

- [x] Add a fixture where the recursive `sync.Once.Do()` call is in a **separate function** (the closure calls a named function that calls `.Do()` again) — this is the harder case because the detector must walk up the call chain
- [x] BP-15 currently only tests a direct recursive closure; the separate-function case may not be detected

---

## Phase 2 — Metadata Refactor (Match CWE/PERF Pattern)

> **Status:** ❌ Not started
> **Effort:** 2–3 days

### 2.1 Create `BadPracticeCategory` enum

- [x] Add `BadPracticeCategory` enum in `src/rules/mod.rs` or a new `src/rules/bp_category.rs`:
  ```rust
  pub enum BadPracticeCategory {
      ErrorHandling,
      Concurrency,
      Panics,
      Testing,
      ApiDesign,
      CodeOrganization,
      ProductionHardening,
      DependencyHygiene,
  }
  ```
- [x] Map each BP rule ID to its category
- [x] Use the enum instead of `category_for_rule_id()` string matching in `src/rules/category.rs`
- [x] Ensure JSON/SARIF/text reporters continue to emit `"category": "bad_practice"` (the enum is for internal dispatch, not output)

### 2.2 Create `ruleset/golang/bad-practices.json`

- [x] Create `ruleset/golang/bad-practices.json` with the same structure as `golang.json`:
  - Per-rule entries: `id`, `title`, `description`, `detection_notes`, `severity`, `category`
  - Reference the existing inline metadata from `metadata.rs` as source
  - Include all 13 MVP rules + placeholders for BP-16..BP-65
- [x] Define a `BadPracticeRuleMetadata` struct in `src/rules/` (analogous to `CweRef` in `src/cwe/reference.rs`)

### 2.3 Codegen from `bad-practices.json`

- [x] Add a `gen_bp.rs` in `build/` that generates `META_BP_N` constants from `ruleset/golang/bad-practices.json`
- [x] Update `build.rs` to invoke the BP codegen
- [x] Replace inline constants in `metadata.rs` with `include!` of the generated code

### 2.4 Verify `--list-rules` and `--explain` for BP

- [x] `--list-rules` should show BP rules with proper category grouping
- [x] `--explain BP-1` should pull from the generated metadata (same as CWE/PERF)
- [x] Remove the inline dispatch table `metadata_for()` if the generated metadata makes it redundant

---

## Phase 3 — P2.5-B: Testing Anti-Patterns (BP-16..BP-25)

> **Status:** ❌ Not started. All rules fire only in `*_test.go` files.
> **Effort:** 1 week

### 3.1 Rule definitions

- [x] **BP-16**: `time.Sleep` in test — detect `time.Sleep` (not in a retry loop). Use `testing.Short()` or a ticker instead.
  - Detection: AST walk for `time.Sleep()` in `*_test.go` files, outside a `for`/`range` retry attempt
- [x] **BP-17**: `t.Error` followed by `t.Fatal` — redundant, should use `t.Errorf` then `return`.
  - Detection: line scan for consecutive `t.Error` + `t.Fatal` calls
- [x] **BP-18**: `t.Error`/`t.Errorf` without `t.FailNow`/`return` — test continues after error.
  - Detection: AST walk for `t.Error` call not followed by `return` or `t.FailNow` within the same block
- [x] **BP-19**: Missing `t.Helper()` on test helper functions.
  - Detection: function called from test that does not call `t.Helper()` as first statement
- [x] **BP-20**: Table-driven test without `t.Run` — all cases in single subtest.
  - Detection: detect `for _, tc := range tests { t.Run(...) }` pattern vs monolithic `for` with manual naming
- [x] **BP-21**: `t.Parallel()` missing in table-driven subtest — detect `t.Run` body without `t.Parallel()`
- [x] **BP-22**: TestMain without `os.Exit` — if `TestMain` is defined but doesn't call `os.Exit(m.Run())`.
  - Detection: AST scan for `func TestMain(m *testing.M)` body missing `os.Exit`
- [x] **BP-23**: `testing.Short()` not checked — detect tests that take >100ms without checking `testing.Short()`
  - Detection (heuristic): function with `t.Run` body > 20 lines and no `testing.Short()` guard
- [x] **BP-24**: Test file without any test functions — file is `*_test.go` but has zero `func Test*` declarations.
  - Detection: file-level scan of `*_test.go` files
- [x] **BP-25**: Test helper returns error instead of calling `t.Fatal` — helper returns `error` when `t.Fatal` would be simpler.
  - Detection: function called from `Test*` functions that returns `error` but doesn't need to (heuristic: if the helper always checks the error and calls `t.Fatal` anyway)

### 3.2 Detection approach

- [x] Add BP-16..BP-25 detection functions to a new `rules/testing.rs` file
- [x] Use `unit.path.ends_with("_test.go")` or file-name check in the `SourceIndex` pre-filter
- [x] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`
- [x] Add metadata constants for BP-16..BP-25 in `metadata.rs` (or generated from codegen)

### 3.3 Test fixtures

- [x] Create 20 fixture files (10 vulnerable + 10 safe) in `tests/fixtures/go/bad_practices/`
- [x] Safe fixtures should use the correct pattern
- [x] Vulnerable fixtures should use `_test.go` suffix
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify via the dedicated `tests/go_bad_practice_integration.rs`

---

## Phase 4 — P2.5-C: API Design + Code Organization (BP-26..BP-45)

> **Status:** ❌ Not started. Requires tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`.
> **Effort:** 2 weeks

### 4.1 API Design (BP-26..BP-35)

- [x] **BP-26**: Context not first parameter in function signature
  - Detection: AST check that `ctx context.Context` is the first param (excluding `(receiver T)`)
- [x] **BP-27**: Exported function returns unexported type
  - Detection: match `func FuncName(...)` (capitalized) returns a type with lowercase first char
- [x] **BP-28**: Interface with a single method — should be a function type instead
  - Detection: `interface_type` with exactly one method
- [x] **BP-29**: Interface with excessive methods (>5) — "interface bloat"
  - Detection: `interface_type` with >5 methods
- [x] **BP-30**: Exported interface without documented implementation in same package
  - Detection: `type X interface { ... }` exported but no concrete type in the same package that implements it (requires type-checking — heuristic: look for `*X` or `X` in method receivers)
- [x] **BP-31**: Function returns concrete type instead of interface
  - Detection: exported function returns a concrete struct type when an interface exists in the same package
- [x] **BP-32**: Error type defined as `string` instead of `struct{...}`
  - Detection: `type X string` with `func (x X) Error() string` — should be struct for structured errors
- [x] **BP-33**: Sentinel error defined as `var ErrX = errors.New(...)` without `Is` method
  - Detection: detect sentinel error without `func Is(err, target) bool` in the same package
- [x] **BP-34**: Error wrapping without `%w` — `fmt.Errorf("msg: %v", err)` vs `fmt.Errorf("msg: %w", err)`
  - Detection: line scan for `fmt.Errorf` with `%v` and an `error` argument
- [x] **BP-35**: Package name does not match directory name
  - Detection: compare `package foo` with directory name

### 4.2 Code Organization (BP-36..BP-45)

- [x] **BP-36**: `init()` function with side effects (HTTP registration, file writes, etc.)
  - Detection: AST walk inside `init()` body for non-variable-declaration statements that cause observable side effects
- [x] **BP-37**: Package-level mutable global variable
  - Detection: `var x = ...` (not `const`, not `var _ = ...`) at package level, not in test files — detect with tree-sitter `var_declaration` at the file's top-level
- [x] **BP-38**: Unexported helper with no internal callers within the package
  - Detection: count references to the unexported function within the same package; warn if zero
- [x] **BP-39**: Exported function without doc comment
  - Detection: exported function/type without preceding `// Comment` or `/* Comment */`
- [x] **BP-40**: Package-level var/const block not used for related declarations
  - Detection: `const ( ... )` with unrelated constants (heuristic: check name prefixes differ)
- [x] **BP-41**: File header missing package doc comment
  - Detection: first line of `.go` file is not `// Package ...` or `/* ... */` before `package`
- [x] **BP-42**: Import alias not used consistently
  - Detection: `import alias "pkg"` where the alias appears only once in the file
- [x] **BP-43**: Dot import (`import . "pkg"`) used outside test files
  - Detection: line scan for `import . "` with file not ending in `_test.go`
- [x] **BP-44**: Blank import (`import _ "pkg"`) without `init()` or driver justification
  - Detection: `import _ "pkg"` where the package has no `init()` or driver pattern (heuristic: only `database/sql/driver` or `image` formats are justified)
- [x] **BP-45**: Receiver name inconsistent across methods of the same type
  - Detection: methods with receiver `(t *T)` and `(this *T)` on the same type — inconsistent naming

### 4.3 Detection approach

- [x] Add BP-26..BP-45 detection functions to new files:
  - `rules/api_design.rs` (BP-26..BP-35)
  - `rules/code_organization.rs` (BP-36..BP-45)
- [x] Use tree-sitter queries for `interface_type`, `type_spec`, `method_declaration`, `var_declaration`
- [x] Register in `BAD_PRACTICE_RULES` in `dispatch.rs`
- [x] Add metadata constants for BP-26..BP-45 in `metadata.rs`

### 4.4 Test fixtures

- [x] Create 40 fixture files (20 vulnerable + 20 safe) in `tests/fixtures/go/bad_practices/`
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify via `tests/go_bad_practice_integration.rs`

---

## Phase 5 — P2.5-D: Production Hardening + Dependency Hygiene (BP-46..BP-65)

> **Status:** ❌ Not started. Co-developed with P2.1 taint for some rules.
> **Effort:** 2 weeks

### 5.1 Production Hardening (BP-46..BP-55)

- [x] **BP-46**: HTTP server without `ReadTimeout`/`WriteTimeout`
  - Detection: detect `http.Server{}` without `.ReadTimeout` or `.WriteTimeout` set
- [x] **BP-47**: No graceful shutdown (`Shutdown` not called)
  - Detection: detect `http.Server.ListenAndServe` without `Shutdown` in signal handler
- [x] **BP-48**: `log.Fatal`/`os.Exit` in non-main function
  - Detection: AST walk for `log.Fatal` or `os.Exit` outside `main()` / `init()`
- [x] **BP-49**: Deferred function without error handling
  - Detection: `defer func() { ... }()` where the func body ignores errors (heuristic: uses `_ =` or no assignment of error return)
- [x] **BP-50**: No signal handling for `SIGTERM`/`SIGINT` in long-running process
  - Detection: detect `main()` with `http.ListenAndServe` or `for {}` without `signal.Notify`
- [x] **BP-51**: Panic recovery without re-panic in library code
  - Detection: `defer recover()` without `panic(err)` in library (non-main) code
- [x] **BP-52**: Integer overflow in arithmetic (heuristic: multiplication without bounds check)
  - Detection: AST walk for `*` operator with both operands being `int`/`int64` types (no preceding bounds check)
- [x] **BP-53**: `encoding/gob` registered types not matching
  - Detection: detect `gob.Register` calls where the registered type is different from the expected decode target
- [x] **BP-54**: No rate limiting on public HTTP endpoint
  - Detection: detect exported `http.HandlerFunc` or `http.Handler` without rate-limiting middleware
- [x] **BP-55**: Missing `RequestID` propagation in middleware chain
  - Detection: detect middleware chain where context-based request ID is not carried through

### 5.2 Dependency Hygiene (BP-56..BP-65)

- [x] **BP-56**: Deprecated stdlib package used (`ioutil`, `golang.org/x/net/context`)
  - Detection: check `go.mod` or `import` for known-deprecated packages (Go 1.16+: `io/ioutil` → `io`/`os`, `context` → stdlib)
- [x] **BP-57**: Old Go version in `go.mod` (>2 minor versions behind latest)
  - Detection: check `go 1.xx` in `go.mod` against current stable version
- [x] **BP-58**: Unpinned dependency version (`v1.x` instead of `v1.2.3`)
  - Detection: check `go.mod` `require` lines for `v1.x` (missing patch/minor pin)
- [x] **BP-59**: Direct dependency not used in any import
  - Detection: check `go.mod` required modules against actual imports in the project (requires project-level scan)
- [x] **BP-60**: Test dependency in main `go.mod` (not in `go.test.mod` or `tools.go`)
  - Detection: check test-only packages in `require` block vs only imported in `*_test.go` files
- [x] **BP-61**: Indirect dependency not listed in `go.mod` (Go 1.17+ requires `// indirect` comments)
  - Detection: check `go.mod` for missing `// indirect` comments on indirect dependencies
- [x] **BP-62**: Dependency used only in one file, could be internalized
  - Detection: dependency imported in exactly one file with a small API surface (<3 exported functions used)
- [x] **BP-63**: Dependency with known security advisory (CVE) not updated
  - Detection: integrate with `go list -json -m -u all` advisory data or `golang.org/x/vuln`
- [x] **BP-64**: Replace directive in `go.mod` pointing to local filesystem
  - Detection: detect `replace example.com/pkg => ../local/path` in non-development builds
- [x] **BP-65**: `go.sum` missing entries
  - Detection: detect `require` entries without corresponding `go.sum` entry

### 5.3 Detection approach

- [x] Add BP-46..BP-65 detection functions to new files:
  - `rules/production_hardening.rs` (BP-46..BP-55)
  - `rules/dependency_hygiene.rs` (BP-56..BP-65)
- [x] BP-56..BP-65 need `go.mod` parsing — integrate with existing `src/engine/dependencies/` infrastructure
- [x] BP-57, BP-58, BP-61, BP-64, BP-65 are project-level scans (not per-file)
- [x] Register in `BAD_PRACTICE_RULES` in `dispatch.rs` (per-file rules) or add a new project-level BP detector for project-wide rules
- [x] Add metadata constants for BP-46..BP-65 in `metadata.rs`

### 5.4 Test fixtures

- [x] Per-file rules: create fixture files in `tests/fixtures/go/bad_practices/`
- [x] Project-level rules: create fixture directories with `go.mod` + `.go` files
- [x] Register in `tests/fixtures/manifest.toml`

---

## Reserved — BP-12, BP-14 (Goroutine Leak Detection)

> **Status:** ⏳ Reserved. Depends on P2.1 Phase F (inter-procedural taint).

- [x] **BP-12**: Unbuffered channel send from multiple goroutines without adequate receivers — implemented as heuristic in `sync.rs` (detect unbuffered channels + multiple goroutine sends without receiver fan-in)
- [x] **BP-14**: Goroutine without `ctx.Done` select — implemented as heuristic in `sync.rs` (detect goroutines with context.Context but no select on ctx.Done)

These ship with P2.1 Phase 2 (inter-procedural taint) and are tracked in `01-taint-tracking-remaining.md`.

---

## Documentation

- [x] Create `documents/bad-practices.md` — one paragraph per BP rule with rationale and canonical fix. Source: `plans/v2.0.0/antipattern-remediation/bad-practices-scope.md` (also tracked in `05-cross-cutting-remaining.md`)

---

## Quick reference

| Workstream | Items | Rules | Effort | Status |
|-----------|-------|-------|--------|--------|
| MVP Hygiene | 4 items | BP-1..BP-11, BP-13, BP-15 | 2–3d | ⏳ |
| Metadata refactor | 4 items | All BP | 2–3d | ❌ |
| Phase 2 (Testing) | 10 rules | BP-16..BP-25 | 1w | ❌ |
| Phase 3 (API + Code Org) | 20 rules | BP-26..BP-45 | 2w | ❌ |
| Phase 4 (Prod + Dep) | 20 rules | BP-46..BP-65 | 2w | ❌ |
| Reserved | 2 rules | BP-12, BP-14 | — | ⏳ |
| Documentation | 1 doc | `documents/bad-practices.md` | 1d | ❌ |
