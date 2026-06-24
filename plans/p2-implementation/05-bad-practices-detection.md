# P2.5 — Bad Practices Detection (Scope & Design)

> **Parent:** `plans/p2.md` — P2.5
> **Status:** ✅ **Scoping and design complete.** See [`plans/bad-practices-scope.md`](../../bad-practices-scope.md) for the final scope, MVP rule list, architecture decision, and phased roadmap. Implementation deferred to a separate follow-up plan (`P2.5-A`).
> **Estimated effort:** Scoping/design was ~1 week. Implementation will be ~7 weeks split across 4 phases (MVP 2w + 3 follow-up phases of 1-2w each).

---

## Overview

Define the scope, taxonomy, and detection strategy for "bad practices" detection in Go code. This is a new category beyond CWE (security) and PERF (performance), covering general software engineering anti-patterns.

---

## Phase 1: Scope Definition

### 1.1 Define the "bad practices" taxonomy

- [ ] Conduct research on existing Go anti-pattern catalogs:
  - [ ] Go Wiki — CommonMistakes: https://github.com/golang/go/wiki/CommonMistakes
  - [ ] Go CodeReviewComments: https://github.com/golang/go/wiki/CodeReviewComments
  - [ ] "100 Go Mistakes and How to Avoid Them" by Teiva Harsanyi (catalog patterns from the book's table of contents)
  - [ ] Uber Go Style Guide anti-patterns
  - [ ] Google Go Style Guide — decisions and best practices
  - [ ] Effective Go — "Don't do this" sections
  - [ ] Dave Cheney's blog posts on Go patterns
  - [ ] staticcheck checks beyond what slopguard already covers
  - [ ] go-critic checker list
  - [ ] revive rule list
  - [ ] gosec non-security checks (if any)
- [ ] Create a catalog of candidate patterns in `plans/bad-practices-candidates.md`
  - [ ] For each candidate: source, pattern description, severity, detection difficulty
  - [ ] Mark candidates already covered by existing CWE/PERF rules (deduplication)

### 1.2 Define sub-categories

- [ ] **Error Handling Anti-patterns**:
  - [ ] Ignoring errors: `_ = doSomething()` — silent error discard
  - [ ] `if err != nil { return err }` without wrapping context
  - [ ] Panic in library code (not main package)
  - [ ] `recover()` without logging the error
  - [ ] Multiple error checks that could be combined
  - [ ] Returning unexported error types that can't be checked with `errors.Is`
  - [ ] `errors.New` vs `fmt.Errorf` misuse
  - [ ] Not checking `Close()` error return
  - [ ] Shadowing `err` in nested blocks

- [ ] **Concurrency Anti-patterns**:
  - [ ] Goroutine leaks (no cancellation/context propagation)
  - [ ] `sync.WaitGroup.Add()` inside a goroutine body
  - [ ] `sync.Mutex` copy (passed by value)
  - [ ] Channel that is never closed when writers finish
  - [ ] `select {}` with no default or timeout (blocks forever)
  - [ ] `time.After` inside a `select` in a loop (memory leak)
  - [ ] Using `defer` inside a loop (defers at function scope, not block scope)
  - [ ] `sync.Once` usage: `Do` called with a function that panics

- [ ] **Testing Anti-patterns**:
  - [ ] `time.Sleep` in tests instead of synchronization
  - [ ] Test functions that do `os.Exit` or `log.Fatal`
  - [ ] `t.Error` followed by `t.Fatal` (redundant)
  - [ ] Table-driven tests missing `t.Run()` or name
  - [ ] Testing unexported functions (fragile tests)
  - [ ] `TestMain` without calling `os.Exit(m.Run())`

- [ ] **API Design Anti-patterns**:
  - [ ] Interface with >3 methods (Go proverb: "The bigger the interface, the weaker the abstraction")
  - [ ] Exported interface in a package with no unexported implementation
  - [ ] Constructor returning unexported concrete type (limits testability)
  - [ ] Public fields in a struct (breaks encapsulation)
  - [ ] Method receiver name inconsistent across methods of the same type
  - [ ] `context.Context` stored in a struct field

- [ ] **Code Organization Anti-patterns**:
  - [ ] `init()` function with side effects (hard to test, order-dependent)
  - [ ] Circular imports (detect at module level, not file level)
  - [ ] Package name differing from directory name
  - [ ] Multiple packages in one directory
  - [ ] Package-level mutable global variables

- [ ] **Production Hardening Checks**:
  - [ ] HTTP server started without `ReadTimeout`/`WriteTimeout`/`IdleTimeout`
  - [ ] `http.ListenAndServe` without graceful shutdown (`Shutdown` method)
  - [ ] Missing health check endpoint
  - [ ] Database connection pool misconfiguration: `SetMaxOpenConns(0)` without explicit `SetMaxIdleConns`
  - [ ] `log.Fatal` or `os.Exit` in handler or middleware
  - [ ] No `recover` middleware for HTTP handlers (missing panic recovery)
  - [ ] Missing `X-Content-Type-Options: nosniff` or other security headers (could overlap with CWE)

- [ ] **Dependency Hygiene**:
  - [ ] Direct dependency on a deprecated Go package (`golang.org/x/...` deprecated packages)
  - [ ] Using `ioutil` (deprecated in Go 1.16+)
  - [ ] `go.mod` with `// indirect` dependencies that could be direct
  - [ ] Very old Go version in `go.mod` (`go 1.12` when 1.21+ is available)

### 1.3 Determine which candidates are in scope

- [ ] **In scope**: Patterns that are:
  - [ ] Statically detectable (AST/pattern-based, no runtime info needed)
  - [ ] Not already covered by existing CWE or PERF rules
  - [ ] Not already covered by standard Go tooling (`go vet`, `staticcheck`, `golangci-lint` defaults)
  - [ ] Application-level (not language-level syntax preferences)
  - [ ] High-signal, low-noise (few false positives)
- [ ] **Out of scope**:
  - [ ] Stylistic preferences (use `gofmt`, `goimports`, `revive` for those)
  - [ ] Language-level `go vet` checks (already covered)
  - [ ] Runtime profiling patterns (needs dynamic analysis)
  - [ ] Naming conventions beyond what's universally agreed upon
- [ ] Document in-scope candidates in `plans/bad-practices-scope.md` with justification

### 1.4 Determine rule ID scheme

- [ ] Propose rule ID prefix: `BP-` (Bad Practice) or `GP-` (Good Practice) or `QA-` (Quality Assurance)
- [ ] Decision: [ ] Choose one and document rationale
- [ ] Numbering: sequential starting from 1 (e.g., `BP-1`, `BP-2`, ...)
- [ ] Separate category in `ruleset/golang/golang.json` or a new ruleset file (`ruleset/golang/bad-practices.json`)?
  - [ ] Decision: [ ] New file for separation of concerns, OR add to existing file for unified catalog

---

## Phase 2: Detection Strategy

### 2.1 Detector architecture decisions

- [ ] **Option A**: Single `GoBadPracticeScan` detector (like GoCweScan, GoPerfScan) with domain modules
  - [ ] Pros: Consistent with existing architecture, single entry point
  - [ ] Cons: Another 100+ rules in one detector struct gets unwieldy
- [ ] **Option B**: Multiple smaller detectors by sub-category (e.g., `ErrorHandlingDetector`, `ConcurrencyDetector`)
  - [ ] Pros: Better separation, easier to disable per-category
  - [ ] Cons: More detector structs, more boilerplate
- [ ] **Option C**: Per-rule standalone detectors (like Python's ReCompileInLoop)
  - [ ] Pros: Maximum isolation
  - [ ] Cons: Verbose, lots of boilerplate
- [ ] Decision: [ ] Choose one and document rationale

### 2.2 Rule metadata design

- [ ] Define `BadPracticeRuleMetadata` or extend `RuleMetadata`:
  - [ ] `id: &'static str`
  - [ ] `title: &'static str`
  - [ ] `description: &'static str`
  - [ ] `category: BadPracticeCategory` (new enum: ErrorHandling, Concurrency, Testing, APIDesign, CodeOrg, ProductionHardening, DependencyHygiene)
  - [ ] `severity: Severity`
  - [ ] `fix: Option<&'static str>`
  - [ ] No `cwe` field (bad practices don't map to CWE)

### 2.3 Detection approach per sub-category

- [ ] **Error Handling**: Mostly AST pattern matching on `if err != nil` blocks, `:=` assignments, `_` discards
  - [ ] Use existing `GoUnitFacts` + tree-sitter queries
- [ ] **Concurrency**: AST pattern matching + scope analysis (`sync.Mutex` position in struct vs function body)
  - [ ] May need new facts extraction for goroutine/select/channel patterns
- [ ] **Testing**: AST pattern matching on `*_test.go` files, `*testing.T` receiver patterns
  - [ ] Only scan test files (`.go` files matching `*_test.go` or containing `_test` package)
- [ ] **API Design**: AST pattern matching on exported types, interfaces, method receivers
  - [ ] Need AST queries for `type_spec`, `interface_type`, `method_declaration`
- [ ] **Code Organization**: AST pattern matching + some multi-file analysis (circular imports)
  - [ ] Multi-file analysis can be heuristic initially (single-file approximations)
- [ ] **Production Hardening**: AST pattern matching on `http.Server` initialization, `main` function patterns
  - [ ] Need call-site analysis for `ListenAndServe`, `ListenAndServeTLS`
- [ ] **Dependency Hygiene**: Go module file parsing (`go.mod`) + import analysis
  - [ ] Check `go.mod` for `go` directive version, deprecated packages in `require`
  - [ ] Check `.go` files for `ioutil` imports

### 2.4 Fact extraction needs

- [ ] Identify new tree-sitter queries needed:
  - [ ] `interface_type` — for API design checks
  - [ ] `type_spec` — for exported types
  - [ ] `method_declaration` — for receiver name consistency
  - [ ] `call_expression` with `selector_expression` for `http.ListenAndServe`
  - [ ] `for_statement` with body analysis for `defer` in loop detection
  - [ ] `select_statement` for goroutine leak detection
- [ ] Evaluate whether existing `GoUnitFacts` / `GoPerfFacts` can be reused or if a new `GoBadPracticeFacts` is needed
- [ ] Decision: [ ] Extend existing facts vs. create a dedicated `GoBadPracticeFacts`

---

## Phase 3: Integration Planning

### 3.1 Language plugin integration

- [ ] Add bad practices detector to `src/lang/go/detectors/mod.rs::all()`:
  ```rust
  vec![
      Box::new(GoCweScan::new()),
      Box::new(GoPerfScan::new()),
      Box::new(GoBadPracticeScan::new()), // NEW
  ]
  ```
- [ ] Register in `lang/mod.rs` if needed (likely automatic via existing plugin structure)

### 3.2 Ruleset integration

- [ ] Add rule descriptions to `ruleset/golang/bad-practices.json` (or `golang.json`)
- [ ] Update `build.rs` to generate metadata constants for `BP-*` rules
- [ ] Update `builtin_rule_catalogue()` to include BP rules
- [ ] Update `--list-rules` to show BP rules (with category filter)
- [ ] Update `--explain` to support `BP-*` rule IDs

### 3.3 CLI integration

- [ ] Add category filter: `--category bad-practices` or `--bp-only` flag
- [ ] `--only BP-1,BP-2` should work via existing `--only`/`--skip` mechanism
- [ ] Default: BP rules enabled (unless user opts out via config)

### 3.4 Reporting integration

- [ ] Update text reporter to show BP rules with appropriate coloring/icon (different from CWE/PERF)
- [ ] Update JSON reporter to include `category: "bad_practice"` field
- [ ] Update SARIF reporter to map BP findings appropriately (non-security results)

### 3.5 Configuration integration

- [ ] Add `[bad_practices]` section to `SlopguardConfig`:
  ```toml
  [bad_practices]
  enabled = true                # default: true
  severity = "medium"            # default minimum severity
  only = ["BP-1", "BP-10"]      # optional: only specific rules
  skip = ["BP-4"]                # optional: skip specific rules
  ```
- [ ] Update `slopguard.schema.json`

---

## Phase 4: Prioritization

### 4.1 Rank candidates by impact

- [ ] Score each candidate on:
  - [ ] **Signal**: How likely to catch real bugs? (1-5)
  - [ ] **Noise**: How many false positives expected? (1-5, lower is better)
  - [ ] **Effort**: How complex is the detector? (1-5, lower is better)
  - [ ] **Uniqueness**: Is this pattern already caught by other tools? (1-5, higher = more unique to slopguard)
  - [ ] **User Value**: Would a developer act on this finding? (1-5)
- [ ] Sort by composite score: `signal + uniqueness + userValue - noise - effort/2`
- [ ] Select top ~30-50 candidates for initial implementation
- [ ] Document prioritization in `plans/bad-practices-prioritization.md`

### 4.2 Create phased roadmap

- [ ] **Phase 1** (MVP): Top 15 rules — target: error handling + concurrency basics
- [ ] **Phase 2**: Next 15 rules — target: testing + API design
- [ ] **Phase 3**: Next 20 rules — target: production hardening + code organization
- [ ] **Phase 4**: Remaining rules — target: dependency hygiene + edge cases

---

## Phase 5: Deliverables for This Plan

### 5.1 Research documents

- [x] [`plans/bad-practices-scope.md`](../../bad-practices-scope.md) — final scope, MVP list, architecture, prioritization, and phased roadmap. The "candidates catalog" research was folded into the scope doc to keep the deliverables list small.
- [ ] `plans/bad-practices-candidates.md` — superseded by `bad-practices-scope.md` §3 (MVP rules table). Future candidates cataloging is tracked per-phase.
- [ ] `plans/bad-practices-prioritization.md` — superseded by `bad-practices-scope.md` §3 + §9 (phased roadmap with gates).

### 5.2 Design documents

- [x] Detector architecture: `bad-practices-scope.md` §4 (Option A: single `GoBadPracticeScan` with domain submodules).
- [x] Rule metadata: `bad-practices-scope.md` §5.
- [x] Ruleset format: `bad-practices-scope.md` §6.
- [x] Registry: `bad-practices-scope.md` §6 + §11 (no separate registry.toml doc needed; mirrors the existing `registry.toml` + `build.rs` flow).

### 5.3 Implementation-readiness checklist

- [x] All MVP sub-category scopes defined and reviewed
- [x] Detection approach documented for each candidate
- [x] Fact extraction needs enumerated
- [x] Integration points identified in existing codebase
- [x] Rule ID scheme selected (`BP-N`)
- [x] Prioritized list ready for Phase 1 implementation
- [x] Go/no-go decision: deferred to P2.5-A kickoff (no blockers identified)

---

## Dependencies

- Existing detector architecture (`src/core/detector.rs`, `src/lang/go/detectors/cwe/mod.rs`, `src/lang/go/detectors/perf/mod.rs`)
- Existing fact extraction infrastructure (`src/lang/go/detectors/cwe/facts.rs`, `src/lang/go/detectors/perf/facts.rs`)
- Registry.toml + build.rs code generation pipeline
- `ruleset/golang/golang.json` (or new file) for rule descriptions
- `slopguard.toml` configuration structure
- CLI argument definitions (`src/cli/mod.rs`)
- Reporter modules (`src/reporting/text.rs`, `json.rs`, `sarif.rs`)
