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
- [x] Cross-function return propagation — implemented via `finalize()` in `mod.rs:121` with project-level call graph merging, param/return/output-pointer propagation

### 2.4 Edge cases

- [x] Pointer/reference aliasing: `a := &b; *a = tainted` — implemented via `output_pointer_params` in summary.rs, IP-011 fixture (commit f390c5a)
- [x] Struct field assignments: `obj.Field = tainted; sink(obj.Field)` — tracked through variable nodes
- [x] Map/slice mutations: `m[key] = tainted; sink(m[key])` — implemented via map/slice write bridge in build.rs (commit cd34160)
- [~] Defer statements: tainted data in defer closure — not implemented (deferred → see plans/v3.0.0/)
- [x] Goroutine closures: tainted data captured by closure — implemented via channel send/receive taint tracking (commit cd34160)
- [~] Type assertions and conversions: `x := v.(string)` — not implemented (deferred → see plans/v3.0.0/)

---

## Phase 3: Inter-Procedural Analysis (Intra-File)

### 3.1 Build a call graph

- [x] Implement `extract_call_graph(unit: &ParsedUnit) -> CallGraph` (in `extract/call_graph.rs:8`; different signature from plan but functional)
- [x] `CallGraph`: struct with `sites: Vec<CallSite>`, `declarations: HashMap<SharedText, FunctionDecl>` (in `model.rs:268`)
- [~] `CallGraphNode` as specified (with `is_exported`, `taint_summary`, `callees`, `callers`) — not implemented as a single struct; separate `FunctionDecl` and `TaintSummary` exist (deferred → see plans/v3.0.0/)
- [x] `TaintSummary { taints_params: Vec<usize>, returns_taint: bool, sanitizes: bool }` — exists in `model.rs:292`
- [x] For each function declaration, extract its name and parameter list — in `extract/call_graph.rs:25-42`
- [x] For each call expression within a function, record the edge: `caller → callee` — in `extract/call_graph.rs:55-100`
- [x] Handle method calls: `receiver.Method(args)` — `extract/call_graph.rs:44` handles `method_declaration`
- [~] Handle selectors: `pkg.Func(args)` — external functions not resolved with summaries (deferred → see plans/v3.0.0/)

### 3.2 Compute taint summaries per function

- [x] Implement `compute_summary_for(graph, annotations, source, func_name, params) -> TaintSummary` (in `graph_query/summary.rs:37`)
- [x] `taints_params`: which parameter indices pass through to sinks without sanitization
- [x] `returns_taint`: whether the return value can be tainted
- [x] `sanitizes`: whether the function applies a sanitizer to its parameters before use
- [~] Store summary on each `CallGraphNode` — summaries stored in HashMap, not on a CallGraphNode struct (deferred → see plans/v3.0.0/)

### 3.3 Propagate taint across call edges

- [x] Implement `propagate_inter_procedural(call_graph, intra_paths)` — implemented in `mod.rs:121-258` via `finalize()` with project-level call graph merging, param/return/output-pointer propagation (commit f9db01d)
- [x] Topological sort of call graph — implemented implicitly via `merge_call_graphs` + `func_to_file` resolution
- [x] For each call edge `A → B`: — implemented in `finalize()` iteration over `project_cg.calls`
- [x] If `A` passes tainted data as argument `i` to `B`: — checks `callee_summary.param_sources` against caller arguments
- [x] And `B`'s summary shows `param_i` reaches a sink: — wired via `find_callee_summary()` → `param_sources` lookup
- [x] Then emit an inter-procedural taint path — `emit_inter_procedural_finding()` at `mod.rs:490`
- [~] Handle recursive functions: limit depth — not implemented (deferred → see plans/v3.0.0/)
- [~] Handle mutual recursion: use visited set — not implemented (deferred → see plans/v3.0.0/)

### 3.4 Handle external functions

- [~] Build a static "builtin summary" table for common stdlib functions — not implemented (deferred → see plans/v3.0.0/)
- [~] `filepath.Clean` → sanitizes first argument, returns clean — sink/source classification exists in `extract/classify.rs` but no summary table per se (deferred → see plans/v3.0.0/)
- [~] `html.EscapeString` → sanitizes first argument, returns clean (deferred → see plans/v3.0.0/)
- [~] `sql.Open` → returns a DB handle (deferred → see plans/v3.0.0/)
- [~] `url.Parse` → returns parsed URL (deferred → see plans/v3.0.0/)
- [~] `json.Unmarshal` → deserializes into target (deferred → see plans/v3.0.0/)
- [~] `template.Must` → wraps template (deferred → see plans/v3.0.0/)
- [~] When resolving a call to an external function, use the builtin summary (deferred → see plans/v3.0.0/)

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

- [x] CWE-90 taint rule implemented in `taint/rules/cwe_90.rs:10` with `SinkKind::LDAPQuery`
- [x] CWE-91 taint rule implemented in `taint/rules/cwe_91.rs:10` with `SinkKind::XPathQuery`
- [x] Detect appropriate sanitizers: `SanitizerKind::LDAP` and `SanitizerKind::XPath`

### 4.6 Constraint: Two-hop limit (Phase 1-2 scope)

- [~] Track taint through at most 2 assignment hops — no hop-limit logic in codebase (deferred → see plans/v3.0.0/)
- [~] Three or more hops → fall back to pattern match (deferred → see plans/v3.0.0/)
- [~] Cross-function hops count toward the limit (deferred → see plans/v3.0.0/)
- [~] Log a debug-level message when taint propagation is truncated (deferred → see plans/v3.0.0/)

---

## Phase 5: Sanitizer Detection & Confidence Scoring

### 5.1 Enhance sanitizer detection

- [x] Detect custom sanitizer functions by name heuristics — ponytail comment at `classify.rs:152`, name-based heuristic catches user-defined sanitize/clean/escape
- [x] Function names containing `sanitize`, `clean`, `escape`, `validate`, `safe`, `check`
- [~] Function names matching `isValid*`, `check*`, `verify*` — not explicitly checked (deferred → see plans/v3.0.0/)
- [x] Detect validation patterns: `regexp.MustCompile(...)` — implemented in `classify.rs:129-130` via `regexp.*.MatchString` → `SanitizerKind::Validation`
- [x] `strconv.Atoi(input)` with error check before use — implemented in `classify.rs:132-138` (strconv.Atoi/ParseInt/ParseFloat/ParseUint → Validation)
- [~] `if input == expected` before use (deferred → see plans/v3.0.0/)
- [~] `switch input { case "a", "b": ... }` before use (deferred → see plans/v3.0.0/)
- [~] Detect type assertion as sanitization (deferred → see plans/v3.0.0/)

### 5.2 Implement confidence scoring

- [x] `confidence: Option<f32>` field exists on `Finding` struct (`finding.rs:133`) and `FindingWire` — but per-taint-path scoring not implemented
- [~] Base confidence = 1.0 with hop-based multipliers — scoring formula not applied (deferred → see plans/v3.0.0/)
- [~] Multiply by 0.9/0.8/0.7/0.5 — not implemented (deferred → see plans/v3.0.0/)
- [~] Findings with confidence < 0.5 downgraded to Info — not implemented (deferred → see plans/v3.0.0/)

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
- [~] Limit taint extraction to files that contain at least one source AND one sink (quick pre-scan) — not implemented (deferred → see plans/v3.0.0/)
- [x] Avoid duplicating tree-sitter queries: reuse existing `walk_calls_and_assignments` shared path
- [~] Benchmark: taint analysis overhead on full codehound self-scan — not benchmarked (deferred → see plans/v3.0.0/)
- [~] Target: <2× slowdown for files with taint sources (deferred → see plans/v3.0.0/)
- [~] Target: negligible overhead for files without sources/sinks (<5%) (deferred → see plans/v3.0.0/)
- [~] Add a `--max-taint-depth` CLI flag — not implemented (deferred → see plans/v3.0.0/)

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
- [~] Create `cross_function_taint.txt` — not created (deferred → see plans/v3.0.0/)
- [~] Create `two_hop_taint.txt` — not created (deferred → see plans/v3.0.0/)
- [~] Create `three_hop_taint.txt` — not created (deferred → see plans/v3.0.0/)
- [~] Create `goroutine_taint.txt` — not created (deferred → see plans/v3.0.0/)
- [~] Create `sanitized_via_validation.txt` — not created (deferred → see plans/v3.0.0/)

### 6.4 Integration tests

- [x] Create `tests/go_taint_integration.rs` — exists (inter-procedural fixtures, tests `#[ignore]`'d)
- [x] Parameterized test for each fixture — written in `go_taint_integration.rs`
- [x] Use `assert_fixture_rules()` helper — exists in `tests/helpers/mod.rs:49`
- [~] Test `--no-taint` flag — CLI flag `--no-taint` exists (`args.rs:68`) but no dedicated integration test (deferred → see plans/v3.0.0/)
- [~] Test confidence scoring — not implemented (deferred → see plans/v3.0.0/)

### 6.5 Regression tests

- [~] Ensure existing CWE detectors still fire when taint is enabled — not regression-tested (deferred → see plans/v3.0.0/)
- [~] Ensure existing safe fixtures still don't fire — not regression-tested (deferred → see plans/v3.0.0/)
- [x] Run full test suite: `cargo test` — passes
- [x] Run benchmarks: `cargo bench` — runs
- [~] Ensure no performance regression on scans with `--no-taint` — not benchmarked (deferred → see plans/v3.0.0/)

---

## Phase 7: Future Extensions (Out of Initial Scope)

### 7.1 Inter-file taint tracking

- [~] Build a project-wide call graph across multiple files — out of initial scope (deferred → see plans/v3.0.0/)
- [~] Resolve imports to local packages — out of initial scope (deferred → see plans/v3.0.0/)
- [~] Track taint across package boundaries — out of initial scope (deferred → see plans/v3.0.0/)

### 7.2 Field-sensitive analysis

- [~] Track taint through individual struct fields — out of initial scope (deferred → see plans/v3.0.0/)
- [~] `obj.Inner.Field = source; sink(obj.Other)` → no finding (deferred → see plans/v3.0.0/)
- [~] `obj.Inner.Field = source; sink(obj.Inner.Field)` → finding (deferred → see plans/v3.0.0/)

### 7.3 Context-sensitive analysis

- [~] Clone taint summaries per call site — out of initial scope (deferred → see plans/v3.0.0/)
- [~] Improves precision at cost of performance (deferred → see plans/v3.0.0/)

### 7.4 Taint tracking for other languages (Python)

- [~] Extend `PythonUnitFacts` with taint annotations — out of initial scope (deferred → see plans/v3.0.0/)
- [~] Implement Python taint extraction using tree-sitter-python (deferred → see plans/v3.0.0/)
- [~] Track Flask/Django request data → sink patterns (deferred → see plans/v3.0.0/)

---

## Dependencies

- Requires the `tree-sitter` crate (already in use) for CST traversal
- Requires the `GoUnitFacts` extraction pipeline (already exists in `src/lang/go/detectors/cwe/facts.rs`)
- Requires the `SourceIndex` infrastructure (already exists in `src/lang/go/detectors/cwe/source_index.rs`)
- Builds on existing function span collection (`ast::collect_function_spans`)
