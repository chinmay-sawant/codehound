# P2.1 — Taint Tracking / Data Flow Analysis

> **Parent:** `plans/p2.md` — P2.1
> **Status:** Phases A (Foundation) + B (Intra-procedural graph + CWE rewrites) **COMPLETED**. Phases C–F **not started**.
> **Estimated effort:** 4-6 weeks for remaining phases (C–F).
> **Pending work breakdown:** `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md`

---

## Overview

Track how user-controlled data flows through assignments, function calls, and returns. Build def-use chains to detect when tainted data reaches a sink (true positive) vs. when sanitized data reaches a sink (true negative).

---

## Phase 1: Foundation — Data Structures & Fact Layer

### 1.1 Design the `TaintGraph` structure

- [x] Define `TaintNode` enum (implemented in `taint/model.rs` as `Source`, `Variable`, `Sink`, `Sanitizer`, `Return`)
  - [x] Variants: `Source { function, kind, byte_range }`, `Variable { name, type_hint, scope, decl_byte }`, `Sink { function, kind, argument_index, byte_range }`, `Sanitizer { function, kind, byte_range }`, `Return { function, index }`
- [x] Define `TaintEdge` struct: `{ from: TaintNodeId, to: TaintNodeId, kind: EdgeKind }`
  - [x] `EdgeKind`: `Assignment`, `PassThrough`, `Return`, `Argument(usize)`
- [x] Define `TaintGraph` struct
  - [x] `nodes: Vec<TaintNode>`, `edges: Vec<TaintEdge>`
  - [x] Index maps: `by_variable: HashMap<(ScopeId, SharedText), Vec<TaintNodeId>>`, `by_sink`, `by_source`
- [x] Define `SourceKind` enum: `UserInput`, `Args`, `EnvVar`, `File`, `Network`
- [x] Define `SinkKind` enum: `CommandExec`, `SQLQuery`, `FileOpen`, `Template`, `HTTPWrite`, `Deserialization`
- [x] Define `SanitizerKind` enum: `Path`, `HTML`, `URL`, `SQL`, `Validation`, `Bounded`

### 1.2 Extend `GoUnitFacts` with taint primitives

- [x] Add `taint: TaintAnnotations` field to `GoUnitFacts` (populated via `extract_taint_facts` in `facts/build.rs:33`)
  - [x] `TaintSourceAnnotation { function, kind, byte_range, result_variable, arguments }`
- [x] Add `taint_graph: Option<TaintGraph>` to `GoUnitFacts` (built via `build_taint_graph_for_facts`)
  - [x] `TaintSinkAnnotation { function, kind, argument_index, argument_text, all_arguments, byte_range }`
- [x] Sanitizer annotations in `TaintAnnotations`:
  - [x] `TaintSanitizerAnnotation { function, kind, byte_range, result_variable, arguments }`
- [x] Assignments detail in `TaintAnnotations`:
  - [x] `AssignmentDetail { lhs, rhs_text, scope, byte_range, from_source_or_sanitizer }`

### 1.3 Implement taint fact extraction

- [x] Implement `extract_taint_facts(unit: &ParsedUnit) -> TaintAnnotations` in `taint/extract/mod.rs`
- [x] Walk the CST for variable declarations (`var x = ...`, `x := ...`)
- [x] Walk the CST for assignment statements (`x = ...`)
- [x] Walk the CST for function calls and their arguments
- [x] Identify taint sources by matching call expressions against known source lists
  - [x] `http.Request.FormValue`, `http.Request.URL.Query()`, `http.Request.PostForm`
  - [x] `os.Args`, `flag.Args()`
  - [x] `os.Getenv`, `os.Environ`
  - [x] `io.ReadAll`, `bufio.Scanner.Text()`, `bufio.Reader.ReadString()`
  - [x] `os.ReadFile`, `os.Open`
- [x] Identify taint sinks by matching call expressions against known sink lists
  - [x] `exec.Command`, `exec.CommandContext`
  - [x] `*sql.DB.Query`, `*sql.DB.Exec`, `*sql.DB.QueryRow`
  - [x] `*sql.Tx.Query`, `*sql.Tx.Exec`
  - [x] `os.Create`, `os.OpenFile`, `os.WriteFile`
  - [x] `template.Execute`, `template.ExecuteTemplate`
  - [x] `http.ResponseWriter.Write`, `fmt.Fprintf` with `http.ResponseWriter`
  - [x] `json.NewDecoder().Decode`, `xml.NewDecoder().Decode`
  - [x] `os/exec.Cmd.Run`, `os/exec.Cmd.Start`, `os/exec.Cmd.Output`
- [x] Identify sanitizers by matching call expressions
  - [x] `filepath.Clean`, `path.Clean`
  - [x] `html.EscapeString`, `template.HTMLEscaper`, `template.JSEscaper`
  - [x] `url.QueryEscape`, `url.PathEscape`
  - [x] Prepared statement patterns: `*sql.DB.Prepare`, `*sql.Stmt.Exec`
  - [x] `regexp.MustCompile(...).MatchString(...)` as validation

### 1.4 Implement scope/resolution tracking via tree-sitter

- [x] Extend `TaintAnnotations` with `scopes: Vec<ScopeInfo>` (in `taint/model.rs`)
  - [x] `ScopeInfo { id, parent, kind, byte_range, function }`
  - [x] `ScopeKind`: `Function`, `Block`, `If`, `For`, `Switch`, `Case`
- [x] Build scope tree during fact extraction (in `taint/extract/mod.rs`)
  - [x] Query tree-sitter for `function_declaration`, `block`, `if_statement`, `for_statement`, `switch_statement`
  - [x] Query tree-sitter for `short_var_declaration` (`:=`), `var_spec` within each scope
- [x] Scope tracking during fact extraction with scope hierarchy
- [x] Function-context tracking for scope resolution

---

## Phase 2: Intra-Procedural Taint Propagation

### 2.1 Build graph from extracted facts

- [x] Implement `build_taint_graph(annotations: &TaintAnnotations) -> TaintGraph` in `taint/graph_query/build.rs`
- [x] Graph construction: add variable nodes, source nodes, sink nodes, sanitizer nodes, return nodes
- [x] Handle short variable declarations (`:=`): creates new variable node with assignment edge
- [x] Handle assignments (`=`): creates assignment edge from RHS to LHS
- [x] Scope-based variable resolution: same-named variables in inner scopes shadow outer
- [x] Handle `call_expression` nodes: argument edges from argument variables to call node

### 2.2 Implement taint propagation rules

- [x] Define taint propagation:
  - [x] If `x = tainted_value` then `x` is tainted
  - [x] If `x = y` and `y` is tainted, then `x` is tainted
  - [x] If `sink(tainted_arg)` and no sanitizer between taint source and sink, emit finding
  - [x] If `sanitizer(tainted_arg)`, the result is clean
- [x] Implement `find_taint_paths(graph, source_kind, sink_kind, allowed_sanitizers) -> Vec<TaintPath>` in `taint/graph_query/query.rs`
- [x] `TaintPath`: `{ source_id, sink_id, node_ids: Vec<TaintNodeId>, sanitized: bool }`
- [x] BFS through graph from sources to sinks
- [x] Track sanitized/unsanitized path states
- [x] When a sink is reached with tainted args, record the path
- [x] When a sanitizer wraps tainted data, mark the result as clean

### 2.3 Handle function returns

- [x] `TaintNode::Return` tracks return sites in the graph
- [x] Return values connected to their source via assignment edges
- [ ] Cross-function return propagation (deferred to inter-procedural phase)

### 2.4 Edge cases

- [ ] Pointer/reference aliasing: `a := &b; *a = tainted` — not implemented
- [x] Struct field assignments: `obj.Field = tainted; sink(obj.Field)` — tracked through variable nodes
- [ ] Map/slice mutations: `m[key] = tainted; sink(m[key])` — not implemented
- [ ] Defer statements: tainted data in defer closure — not implemented
- [ ] Goroutine closures: tainted data captured by closure — not implemented
- [ ] Type assertions and conversions: `x := v.(string)` — not implemented

---

## Phase 3: Inter-Procedural Analysis (Intra-File)

### 3.1 Build a call graph

- [ ] Implement `build_call_graph(functions: &[FunctionSpan], facts: &[GoUnitFacts]) -> CallGraph`
- [ ] `CallGraph`:
  - [ ] `nodes: HashMap<String, CallGraphNode>` (function name → node)
  - [ ] `CallGraphNode { name: String, is_exported: bool, taint_summary: TaintSummary, callees: Vec<String>, callers: Vec<String> }`
  - [ ] `TaintSummary { taints_params: Vec<usize>, returns_taint: bool, sanitizes: bool }`
- [ ] For each function declaration, extract its name and parameter list
- [ ] For each call expression within a function, record the edge: `caller → callee`
- [ ] Handle method calls: `receiver.Method(args)` → resolve receiver type
- [ ] Handle selectors: `pkg.Func(args)` (external — treat as opaque, use precomputed summaries for stdlib)

### 3.2 Compute taint summaries per function

- [ ] Implement `compute_taint_summary(func: &FunctionSpan, intra_analysis: &DefUseChain) -> TaintSummary`
- [ ] `taints_params`: which parameter indices pass through to sinks without sanitization
- [ ] `returns_taint`: whether the return value can be tainted based purely on parameter taint
- [ ] `sanitizes`: whether the function applies a sanitizer to its parameters before use
- [ ] Store summary on each `CallGraphNode`

### 3.3 Propagate taint across call edges

- [ ] Implement `propagate_inter_procedural(call_graph: &CallGraph, intra_paths: &[TaintPath]) -> Vec<TaintPath>`
- [ ] Topological sort of call graph (or iterate to fixed point)
- [ ] For each call edge `A → B`:
  - [ ] If `A` passes tainted data as argument `i` to `B`
  - [ ] And `B`'s summary shows `param_i` reaches a sink
  - [ ] Then emit an inter-procedural taint path: `source_in_A → call_B → sink_in_B`
- [ ] Handle recursive functions: limit depth (max recursion depth = 3)
- [ ] Handle mutual recursion: use visited set with depth tracking

### 3.4 Handle external functions

- [ ] Build a static "builtin summary" table for common stdlib functions
  - [ ] `filepath.Clean` → sanitizes first argument, returns clean
  - [ ] `html.EscapeString` → sanitizes first argument, returns clean
  - [ ] `sql.Open` → returns a DB handle (not tainted from input)
  - [ ] `url.Parse` → returns parsed URL (not tainted, but the raw URL was)
  - [ ] `json.Unmarshal` → deserializes into target (target becomes tainted)
  - [ ] `template.Must` → wraps template, doesn't sanitize
- [ ] When resolving a call to an external function, use the builtin summary instead of graph analysis

---

## Phase 4: Taint-Aware Detector Rewrite

### 4.1 Rewrite CWE-22 (Path Traversal) detector

- [x] Taint-aware `detect_cwe_22_taint()` in `taint/rules/cwe_22.rs`, wired in `cwe/mod.rs` via `build_taint_graph_for_facts`
- [x] Taint paths from user input sources → `os.Open`/`os.OpenFile`/`os.ReadFile` sinks
- [x] Check if any sanitizer (`filepath.Clean`, `path.Clean`) exists on the path
- [x] If tainted and unsanitized → true positive CWE-22
- [x] If tainted and sanitized → suppressed (false positive removal)
- [x] Maintain backward compatibility: fall back to pattern matching if taint graph is empty (no sources identified)

### 4.2 Rewrite CWE-78 (Command Injection) detector

- [x] Taint-aware `detect_cwe_78_taint()` in `taint/rules/cwe_78.rs`
- [x] Taint paths from user input → `exec.Command` args
- [x] Detect sanitization (shellquote, etc.)
- [x] Detect `exec.Command("sh", "-c", userinput)` pattern — explicit shell wrapping

### 4.3 Rewrite CWE-89 (SQL Injection) detector

- [x] Taint-aware `detect_cwe_89_taint()` in `taint/rules/cwe_89.rs`
- [x] Taint paths from user input → SQL query execution
- [x] Detect prepared statements (`db.Prepare`, `stmt.Exec`) as sanitization
- [x] Detect ORM patterns (GORM, sqlx named params) as sanitization
- [x] Detect string concatenation with tainted values as unsanitized

### 4.4 Rewrite CWE-79 (XSS) detector

- [x] Taint-aware `detect_cwe_79_taint()` in `taint/rules/cwe_79.rs`
- [x] Taint paths from user input → HTTP response/output sinks
- [x] Detect `html.EscapeString`, `template.HTMLEscaper` as sanitization

### 4.5 Rewrite CWE-90 (LDAP Injection) and CWE-91 (XPath Injection) similarly

- [ ] Apply taint paths from user input → LDAP/XPath sinks
- [ ] Detect appropriate sanitizers/validators

### 4.6 Constraint: Two-hop limit (Phase 1-2 scope)

- [ ] Track taint through at most 2 assignment hops: `a := source; b := a; sink(b)`
- [ ] Three or more hops → fall back to pattern match
- [ ] Cross-function hops count toward the limit (A→B is one hop)
- [ ] Log a debug-level message when taint propagation is truncated due to hop limit

---

## Phase 5: Sanitizer Detection & Confidence Scoring

### 5.1 Enhance sanitizer detection

- [ ] Detect custom sanitizer functions by name heuristics
  - [ ] Function names containing `sanitize`, `clean`, `escape`, `validate`, `safe`, `check`
  - [ ] Function names matching `isValid*`, `check*`, `verify*`
- [ ] Detect validation patterns:
  - [ ] `regexp.MustCompile(...).MatchString(input)` that gates a sink call
  - [ ] `strconv.Atoi(input)` with error check before use
  - [ ] `if input == expected` before use
  - [ ] `switch input { case "a", "b": ... }` before use
- [ ] Detect type assertion as sanitization: `x, ok := val.(string); if !ok { return }`

### 5.2 Implement confidence scoring

- [ ] Add `confidence: f32` field to each `TaintPath` (0.0–1.0)
- [ ] Base confidence = 1.0
- [ ] Multiply by 0.9 if through one assignment hop, 0.8 if through two hops
- [ ] Multiply by 0.7 if through a function call boundary
- [ ] Multiply by 0.5 if sanitizer detection is heuristic (name-based) vs. proven (stdlib function)
- [ ] Findings with confidence < 0.5 should be downgraded to `Severity::Info` and tagged as `low_confidence`

---

## Phase 6: Integration & Testing

### 6.1 Integrate taint analysis into the scan pipeline

- [x] Add a `taint_enabled: bool` flag to `ScanContext` (in `src/core/scan/context.rs:22`)
- [x] In `detectors/cwe/mod.rs::GoCweScan::run()`:
  - [x] After `GoUnitFacts` extraction, call `build_taint_graph_for_facts` if taint enabled
  - [x] Build `TaintGraph` and propagate taint
  - [x] Pass `TaintGraph` to each domain detector function via `GoUnitFacts.taint_graph`
- [x] Update `rule_ids()` to include taint-aware detector rule IDs
- [x] Ensure `--only`/`--skip` filtering works for taint-aware findings

### 6.2 Performance considerations

- [x] Make taint fact extraction lazy: only extract if taint enabled (`ctx.taint_enabled` guard)
- [ ] Limit taint extraction to files that contain at least one source AND one sink (quick pre-scan)
- [x] Avoid duplicating tree-sitter queries: reuse existing `walk_calls_and_assignments` shared path
- [ ] Benchmark: taint analysis overhead on full slopguard self-scan
  - [ ] Target: <2× slowdown for files with taint sources
  - [ ] Target: negligible overhead for files without sources/sinks (<5%)
- [ ] Add a `--max-taint-depth` CLI flag (default: 3) to limit graph depth

### 6.3 Test fixtures

- [x] Create `tests/fixtures/go/taint/` directory
- [x] Create `CWE-89-vulnerable.txt` (SQL injection taint)
- [x] Create `CWE-89-safe.txt` (prepared statement sanitizer)
- [x] Create `CWE-22-vulnerable.txt` (path traversal taint)
- [x] Create `CWE-22-safe.txt` (filepath.Clean sanitizer)
- [x] Create `CWE-78-vulnerable.txt` (command injection taint)
- [x] Create `CWE-78-safe.txt` (shell quoting sanitizer)
- [x] Create `CWE-79-vulnerable.txt` (XSS taint)
- [x] Create `CWE-79-safe.txt` (HTML escaping sanitizer)
- [ ] Create `cross_function_taint.txt` — not created
- [ ] Create `two_hop_taint.txt` — not created
- [ ] Create `three_hop_taint.txt` — not created
- [ ] Create `goroutine_taint.txt` — not created
- [ ] Create `sanitized_via_validation.txt` — not created

### 6.4 Integration tests

- [ ] Add `tests/go_taint_integration.rs`
- [ ] Parameterized test: for each fixture in `tests/fixtures/go/taint/`, materialize, scan, assert expected rules
- [ ] Use `assert_fixture_rules()` helper pattern from existing test infrastructure
- [ ] Test `--no-taint` flag: same fixtures should fall back to pattern-matching behavior
- [ ] Test confidence scoring: verify low-confidence findings have lower severity

### 6.5 Regression tests

- [ ] Ensure existing CWE detectors still fire on existing fixtures when taint is enabled
- [ ] Ensure existing safe fixtures still don't fire
- [ ] Run full test suite: `cargo test`
- [ ] Run benchmarks: `cargo bench`
- [ ] Ensure no performance regression on scans with `--no-taint`

---

## Phase 7: Future Extensions (Out of Initial Scope)

### 7.1 Inter-file taint tracking

- [ ] Build a project-wide call graph across multiple files
- [ ] Resolve imports to local packages
- [ ] Track taint across package boundaries (same module only)

### 7.2 Field-sensitive analysis

- [ ] Track taint through individual struct fields (not just whole struct)
- [ ] `obj.Inner.Field = source; sink(obj.Other)` → no finding (correct)
- [ ] `obj.Inner.Field = source; sink(obj.Inner.Field)` → finding (correct)

### 7.3 Context-sensitive analysis

- [ ] Clone taint summaries per call site instead of merging all callers
- [ ] Improves precision at cost of performance

### 7.4 Taint tracking for other languages (Python)

- [ ] Extend `PythonUnitFacts` with taint annotations
- [ ] Implement Python taint extraction using tree-sitter-python
- [ ] Track Flask/Django request data → sink patterns

---

## Dependencies

- Requires the `tree-sitter` crate (already in use) for CST traversal
- Requires the `GoUnitFacts` extraction pipeline (already exists in `src/lang/go/detectors/cwe/facts.rs`)
- Requires the `SourceIndex` infrastructure (already exists in `src/lang/go/detectors/cwe/source_index.rs`)
- Builds on existing function span collection (`ast::collect_function_spans`)
