# P2.1 — Taint Tracking / Data Flow Analysis

> **Parent:** `plans/p2.md` — P2.1
> **Status:** Not started. All 275 detectors are substring/pattern matching on source text. Zero inter-procedural analysis.
> **Estimated effort:** 4-6 weeks intra-procedural; 8-12 weeks inter-procedural.

---

## Overview

Track how user-controlled data flows through assignments, function calls, and returns. Build def-use chains to detect when tainted data reaches a sink (true positive) vs. when sanitized data reaches a sink (true negative).

---

## Phase 1: Foundation — Data Structures & Fact Layer

### 1.1 Design the `TaintGraph` structure

- [ ] Define `TaintNode` enum
  - [ ] Variants: `Source { name: String, kind: SourceKind }`, `Variable { name: String, type_hint: Option<String> }`, `Call { function: String, arguments: Vec<usize> }`, `Return { function: String }`, `Sink { kind: SinkKind }`, `Sanitizer { kind: SanitizerKind }`
- [ ] Define `TaintEdge` struct: `{ from: TaintNodeId, to: TaintNodeId, kind: EdgeKind }`
  - [ ] `EdgeKind`: `Assignment`, `PassThrough`, `Return`, `Argument(i)`
- [ ] Define `TaintGraph` struct
  - [ ] `nodes: Vec<TaintNode>`, `edges: Vec<TaintEdge>`
  - [ ] Index maps: `variables: HashMap<String, Vec<TaintNodeId>>`, `calls: HashMap<String, Vec<TaintNodeId>>`
- [ ] Define `SourceKind` enum: `UserInput` (c.Query, r.FormValue, r.URL.Query, os.Args, etc.), `FileRead` (os.ReadFile, ioutil.ReadAll), `EnvVar` (os.Getenv), `Network` (conn.Read, http.Request.Body)
- [ ] Define `SinkKind` enum: `CommandExec` (exec.Command, os/exec), `SQLQuery` (database/sql .Query/.Exec), `FileOpen` (os.Create, os.OpenFile), `TemplateRender` (html/template, text/template), `HTTPResponse` (w.Write, fmt.Fprintf to ResponseWriter), `Deserialization` (json.Unmarshal, xml.Unmarshal, gob.Decode)
- [ ] Define `SanitizerKind` enum: `PathClean` (filepath.Clean), `HTMLEncode` (html.EscapeString), `PreparedStatement` (db.Prepare), `URLEncode` (url.QueryEscape), `ShellEscape` (shlex.Split, shellquote), `JSONValidate` (json.Valid)

### 1.2 Extend `GoUnitFacts` with taint primitives

- [ ] Add `taint_sources: Vec<TaintSourceAnnotation>` to `GoUnitFacts` (`src/lang/go/detectors/cwe/facts.rs`)
  - [ ] `TaintSourceAnnotation { node_id: usize, variable: String, kind: SourceKind, byte_range: Range<usize> }`
- [ ] Add `taint_sinks: Vec<TaintSinkAnnotation>` to `GoUnitFacts`
  - [ ] `TaintSinkAnnotation { node_id: usize, kind: SinkKind, byte_range: Range<usize> }`
- [ ] Add `taint_sanitizers: Vec<TaintSanitizerAnnotation>` to `GoUnitFacts`
  - [ ] `TaintSanitizerAnnotation { node_id: usize, kind: SanitizerKind, byte_range: Range<usize> }`
- [ ] Add `assignments_detail: Vec<AssignmentDetail>` to `GoUnitFacts`
  - [ ] `AssignmentDetail { lhs: String, rhs: RHSExpr, byte_range: Range<usize> }`
  - [ ] `RHSExpr` enum: `Variable(String)`, `Call { function: String, arguments: Vec<RHSExpr> }`, `Literal(String)`, `BinaryOp { op: String, left: Box<RHSExpr>, right: Box<RHSExpr> }`

### 1.3 Implement taint fact extraction

- [ ] Implement `extract_taint_facts(root: &Node, source: &str) -> TaintAnnotations` in `facts.rs`
- [ ] Walk the CST for variable declarations (`var x = ...`, `x := ...`)
- [ ] Walk the CST for assignment statements (`x = ...`)
- [ ] Walk the CST for function calls and their arguments
- [ ] Identify taint sources by matching call expressions against known source lists
  - [ ] `http.Request.FormValue`, `http.Request.URL.Query()`, `http.Request.PostForm`
  - [ ] `os.Args`, `flag.Args()`
  - [ ] `os.Getenv`, `os.Environ`
  - [ ] `io.ReadAll`, `bufio.Scanner.Text()`, `bufio.Reader.ReadString()`
  - [ ] `os.ReadFile`, `os.Open`
- [ ] Identify taint sinks by matching call expressions against known sink lists
  - [ ] `exec.Command`, `exec.CommandContext`
  - [ ] `*sql.DB.Query`, `*sql.DB.Exec`, `*sql.DB.QueryRow`
  - [ ] `*sql.Tx.Query`, `*sql.Tx.Exec`
  - [ ] `os.Create`, `os.OpenFile`, `os.WriteFile`
  - [ ] `template.Execute`, `template.ExecuteTemplate`
  - [ ] `http.ResponseWriter.Write`, `fmt.Fprintf` with `http.ResponseWriter`
  - [ ] `json.NewDecoder().Decode`, `xml.NewDecoder().Decode`
  - [ ] `os/exec.Cmd.Run`, `os/exec.Cmd.Start`, `os/exec.Cmd.Output`
- [ ] Identify sanitizers by matching call expressions
  - [ ] `filepath.Clean`, `path.Clean`
  - [ ] `html.EscapeString`, `template.HTMLEscaper`, `template.JSEscaper`
  - [ ] `url.QueryEscape`, `url.PathEscape`
  - [ ] Prepared statement patterns: `*sql.DB.Prepare`, `*sql.Stmt.Exec`
  - [ ] `regexp.MustCompile(...).MatchString(...)` as validation

### 1.4 Implement scope/resolution tracking via tree-sitter

- [ ] Extend `GoUnitFacts` with `scopes: Vec<ScopeInfo>`
  - [ ] `ScopeInfo { kind: ScopeKind, byte_range: Range<usize>, parent_idx: Option<usize>, variables: HashMap<String, ScopeVar> }`
  - [ ] `ScopeKind`: `Function`, `Block`, `IfBlock`, `ForBlock`, `SwitchBlock`
  - [ ] `ScopeVar { declared_byte: usize, type_hint: Option<String> }`
- [ ] Build scope tree during fact extraction
  - [ ] Query tree-sitter for `function_declaration`, `block`, `if_statement`, `for_statement`, `switch_statement`
  - [ ] Query tree-sitter for `short_var_declaration` (`:=`), `var_spec` within each scope
- [ ] Implement `resolve_variable(scope: &Scope, name: &str) -> Option<ScopeVar>` (walks parent scopes)
- [ ] Add `current_function: Option<String>` tracking during fact extraction (for intra-procedural context)

---

## Phase 2: Intra-Procedural Taint Propagation

### 2.1 Build reaching-definitions analysis per function

- [ ] Implement `build_def_use_chain(facts: &GoUnitFacts, function_span: Range<usize>) -> DefUseChain`
- [ ] `DefUseChain`: For each variable at each program point, track which definition(s) reach that point
- [ ] Handle short variable declarations (`:=`): new definition
- [ ] Handle assignments (`=`): kills previous definition, creates new one
- [ ] Handle `if` / `else` / `for` / `switch` blocks: merge definitions from all paths at join points
- [ ] Handle shadowing: inner scope variable shadows outer scope variable with same name

### 2.2 Implement taint propagation rules

- [ ] Define taint propagation:
  - [ ] If `x = tainted_value` then `x` is tainted
  - [ ] If `x = y` and `y` is tainted, then `x` is tainted
  - [ ] If `x = f(a1, ..., an)` and any `ai` is tainted, then `x` is tainted (unless `f` is a sanitizer)
  - [ ] If `sink(tainted_arg)` and no sanitizer between taint source and sink, emit finding
  - [ ] If `sanitizer(tainted_arg)`, the result is clean
- [ ] Implement `propagate_taint(graph: &mut TaintGraph, facts: &GoUnitFacts) -> Vec<TaintPath>`
- [ ] `TaintPath`: `{ source: TaintNodeId, sink: TaintNodeId, hops: Vec<TaintNodeId>, sanitized: bool }`
- [ ] Walk assignments in order of appearance (within each function)
- [ ] Build a taint set for each variable at each program point
- [ ] When a sink is reached with tainted args, record a path
- [ ] When a sanitizer wraps tainted data, mark the result as clean

### 2.3 Handle function returns

- [ ] If a function returns a tainted value, mark the return site
- [ ] Track `return x` where `x` is tainted
- [ ] Track `return f(args)` where `f` returns tainted

### 2.4 Edge cases

- [ ] Pointer/reference aliasing: `a := &b; *a = tainted` (initial scope: limited to same-scope pointers)
- [ ] Struct field assignments: `obj.Field = tainted; sink(obj.Field)` (two-hop)
- [ ] Map/slice mutations: `m[key] = tainted; sink(m[key])` (two-hop)
- [ ] Defer statements: tainted data in defer closure
- [ ] Goroutine closures: tainted data captured by closure (intra-procedural only)
- [ ] Type assertions and conversions: `x := v.(string)` — carry type forward

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

- [ ] Current: `detect_cwe_22()` in `src/lang/go/detectors/cwe/domains/path_traversal.rs`
  - [ ] Pattern: substring match for `..` or `filepath.Join` with variable args
  - [ ] Gap: Cannot track if `cleanPath(input)` was called before file open
- [ ] New: Build taint graph, find paths from user input sources → `os.Open`/`os.OpenFile`/`os.ReadFile` sinks
- [ ] Check if any sanitizer (`filepath.Clean`, `path.Clean`) exists on the path
- [ ] If tainted and unsanitized → true positive CWE-22
- [ ] If tainted and sanitized → suppressed (false positive removal)
- [ ] Maintain backward compatibility: fall back to pattern matching if taint graph is empty (no sources identified)

### 4.2 Rewrite CWE-78 (Command Injection) detector

- [ ] Current: `detect_cwe_78()` in `src/lang/go/detectors/cwe/domains/injection.rs`
  - [ ] Pattern: `exec.Command` / `exec.CommandContext` with dynamic args
- [ ] New: Taint paths from user input → `exec.Command` args
- [ ] Detect `shlex` / shellquote sanitization as suppression
- [ ] Detect `exec.Command("sh", "-c", userinput)` pattern — explicit shell wrapping

### 4.3 Rewrite CWE-89 (SQL Injection) detector

- [ ] Current: `detect_cwe_89()`
  - [ ] Pattern: `fmt.Sprintf` in SQL query strings, dynamic query building
- [ ] New: Taint paths from user input → SQL query execution
- [ ] Detect prepared statements (`db.Prepare`, `stmt.Exec`) as sanitization
- [ ] Detect ORM patterns (GORM, sqlx named params) as sanitization
- [ ] Detect string concatenation with tainted values as unsanitized

### 4.4 Rewrite CWE-79 (XSS) detector

- [ ] Current: `detect_cwe_79()`
  - [ ] Pattern: `w.Write` or `template.Execute` with user-controlled data
- [ ] New: Taint paths from user input → HTTP response/output sinks
- [ ] Detect `html.EscapeString`, `template.HTMLEscaper` as sanitization

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

- [ ] Add a `taint_enabled: bool` flag to `ScanContext` (default: true, opt-out via `--no-taint`)
- [ ] In `detectors/cwe/mod.rs::GoCweScan::run()`:
  - [ ] After `GoUnitFacts` extraction, call `extract_taint_facts()` if taint enabled
  - [ ] Build `TaintGraph` and propagate taint
  - [ ] Pass `TaintGraph` to each domain detector function (or make it accessible via `GoUnitFacts`)
- [ ] Update `rule_ids()` to include taint-aware detector rule IDs
- [ ] Ensure `--only`/`--skip` filtering works for taint-aware findings

### 6.2 Performance considerations

- [ ] Make taint fact extraction lazy: only extract if at least one taint-aware rule is enabled
- [ ] Limit taint extraction to files that contain at least one source AND one sink (quick pre-scan)
- [ ] Avoid duplicating tree-sitter queries: reuse existing queries where possible
- [ ] Benchmark: taint analysis overhead on full slopguard self-scan
  - [ ] Target: <2× slowdown for files with taint sources
  - [ ] Target: negligible overhead for files without sources/sinks (<5%)
- [ ] Add a `--max-taint-depth` CLI flag (default: 3) to limit graph depth

### 6.3 Test fixtures

- [ ] Create `tests/fixtures/go/taint/` directory
- [ ] Create `vulnerable_sql_injection.txt`:
  - [ ] `lang: go`, source with `c.Query("id")` → `fmt.Sprintf` → `db.Query()`
  - [ ] Expected: CWE-89 fires
- [ ] Create `safe_prepared_statement.txt`:
  - [ ] Same as above but with `db.Prepare()` and `stmt.Exec()`
  - [ ] Expected: CWE-89 does NOT fire
- [ ] Create `vulnerable_path_traversal.txt`:
  - [ ] Source with `r.URL.Query().Get("file")` → `os.Open()`
  - [ ] Expected: CWE-22 fires
- [ ] Create `safe_path_clean.txt`:
  - [ ] Same as above but with `filepath.Clean()` wrapper
  - [ ] Expected: CWE-22 does NOT fire
- [ ] Create `vulnerable_command_injection.txt`:
  - [ ] Source with `os.Args[1]` → `exec.Command()`
  - [ ] Expected: CWE-78 fires
- [ ] Create `safe_shell_escape.txt`:
  - [ ] Source with shell-quoting before `exec.Command`
  - [ ] Expected: CWE-78 does NOT fire
- [ ] Create `cross_function_taint.txt`:
  - [ ] `getDSN()` returns tainted → `sql.Open()` calls it
  - [ ] Expected: CWE-89 fires (inter-procedural)
- [ ] Create `two_hop_taint.txt`:
  - [ ] `a := source; b := a; sink(b)` (two assignments)
  - [ ] Expected: fires
- [ ] Create `three_hop_taint.txt`:
  - [ ] `a := source; b := a; c := b; sink(c)`
  - [ ] Expected: falls back to pattern match (if depth limit hit)
- [ ] Create `goroutine_taint.txt`:
  - [ ] Tainted data captured in goroutine closure → sink inside goroutine
  - [ ] Expected: fires (intra-procedural closure tracking)
- [ ] Create `sanitized_via_validation.txt`:
  - [ ] Input validated via regexp before reaching sink
  - [ ] Expected: does NOT fire

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
