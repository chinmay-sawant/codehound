# P1-F — Inter-Procedural Taint Tracking

> **Parent:** `plans/consolidated_pendingtask_02072026.md` — P1-F row
> **Parent:** `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` — Phase F
> **Status:** Not started
> **Estimated effort:** 3–4 weeks total
> **Depends on:** Phases A/B (intra-procedural graph + CWE rewrites) ✅ Complete

---

## Overview

The current taint tracking is strictly **intra-procedural**: each function is analyzed independently, and taint does not flow across call boundaries. `TaintNode::Return` exists in the data model but is **never created** by the extractor. There is no call graph, no function summary, and no cross-function propagation.

This plan adds inter-procedural taint tracking in 6 phases:

1. **Call graph construction** — build per-file + project-level caller→callee edges
2. **Function summary computation** — per-function `TaintSummary` from intra-procedural analysis
3. **Cross-function propagation** — wire call sites to summaries, add inter-procedural edges
4. **Evidence and reporting** — multi-hop path display, `--taint-show-paths` for inter-procedural flows
5. **Tests and fixtures** — multi-hop fixtures, regression tests, benchmark guard
6. **Edge-case handling** — recursion, pointers, maps, goroutines, deferred calls

---

## Executive Summary

| Phase | Item | Effort | Key Deliverable | Dependencies |
|-------|------|--------|-----------------|-------------|
| 1 | Call graph construction | 5–7d | Per-file + project-level call graph | Tree-sitter call-expression AST |
| 2 | Function summaries | 4–5d | `TaintSummary` struct + computation | Phase 1 (call graph) |
| 3 | Cross-function propagation | 4–5d | Inter-procedural taint edges in graph | Phase 2 (summaries) |
| 4 | Evidence and reporting | 2–3d | Multi-hop path display | Phase 3 (propagation) |
| 5 | Tests and fixtures | 3–4d | 10+ fixture pairs, integration tests | Phase 1–4 |
| 6 | Edge-case handling | 3–4d | Recursion, pointer, map, goroutine support | Phase 3 (propagation) |

---

## Phase 1: Call Graph Construction

### 1.1 Data model for call graph

- [ ] Define `CallGraph` struct in a new file `src/analysis/call_graph.rs` (or inside `taint/graph_query/`):
  ```rust
  /// Per-file call graph: maps callee names to call sites.
  pub struct CallGraph {
      /// caller -> [(callee, call_site_byte_range, arguments)]
      pub calls: HashMap<String, Vec<CallSite>>,
      /// callee -> callers (reverse index)
      pub callers: HashMap<String, Vec<String>>,
  }

  pub struct CallSite {
      pub callee: String,
      pub caller: String,          // enclosing function name
      pub byte_range: Range<usize>,
      pub argument_count: usize,
      pub is_method_call: bool,    // receiver.method(args)
      pub is_closure: bool,        // go func() { ... } or func literal arg
  }
  ```

- [ ] Add `CallGraph` to `GoUnitFacts` in `src/lang/go/detectors/cwe/facts/types.rs`:
  ```rust
  pub call_graph: Option<CallGraph>,
  ```

### 1.2 Per-file call graph extraction

- [ ] Create `extract_call_graph(unit: &ParsedUnit) -> CallGraph` in `src/lang/go/detectors/cwe/taint/extract/call_graph.rs`:
  - Walk all `call_expression` nodes in the tree-sitter CST
  - For each call expression, extract:
    - **Callee name**: `node_text(call.child_by_field_name("function"))`
    - **Caller name**: climb up to the enclosing `function_declaration`/`method_declaration`/`func_literal`
    - **Arguments**: count named children of the `arguments` node
    - **Method call check**: if function is a `selector_expression`, the call is a method call
  - Handle qualified calls: `pkg.Func(args)` → callee is `pkg.Func`
  - Handle method calls: `receiver.Method(args)` → callee is `Type.Method` (approximated as `receiver.Method`)
  - Handle closures: `go func() { ... }()` → callee is `<anonymous>` with `is_closure = true`

- [ ] Handle top-level function declarations:
  ```go
  func helper(x string) string { ... }
  ```
  - The declaration name (`helper`) becomes a potential callee
  - Register in `CallGraph` as a known function with its parameter count

- [ ] Handle method declarations:
  ```go
  func (r *Receiver) Method(x string) { ... }
  ```
  - Callee name: `Receiver.Method` (type + method name)
  - Register in `CallGraph`

- [ ] Wire extraction into `build_go_unit_facts()` in `src/lang/go/detectors/cwe/facts/build.rs`:
  ```rust
  facts.call_graph = Some(extract_call_graph(unit));
  ```
  - This runs unconditionally (always extracts call edges, same as `extract_taint_facts`)

### 1.3 Project-level call graph merge

- [ ] Add `ProjectCallGraph` struct:
  ```rust
  /// Cross-file call graph, built by merging per-file CallGraphs.
  pub struct ProjectCallGraph {
      pub calls: HashMap<String, Vec<CallSite>>,
      pub callers: HashMap<String, Vec<String>>,
      /// Functions declared in the project with their signatures
      pub declarations: HashMap<String, FunctionDecl>,
  }

  pub struct FunctionDecl {
      pub name: String,
      pub param_count: usize,
      pub file: String,
      pub is_method: bool,
      pub receiver_type: Option<String>,
  }
  ```

- [ ] Create `merge_call_graphs(files: &[ParsedUnit]) -> ProjectCallGraph`:
  - Iterate all per-file `CallGraph`s
  - Merge `calls` and `callers` maps
  - Resolve callee names across files: if `helper` is declared in file A and called in file B, create a cross-file edge
  - For unresolved callees (stdlib, third-party), mark as `external`

- [ ] Add `ProjectCallGraph` to `GoUnitFacts` or create a project-level facts container:
  - Option A: Store in `GoUnitFacts` (already per-file, but merged across files during `build_go_unit_facts`)
  - Option B: Create a new `ProjectFacts` struct that holds merged data
  - **Recommendation**: Option B — keep `GoUnitFacts` per-file, add a `project_facts: Arc<ProjectFacts>` shared reference

### 1.4 Name resolution

- [ ] Implement simple local name resolution:
  ```go
  func caller() {
      helper(x)        // <-- callee is "helper" — local function
  }
  func helper(s string) { ... }
  ```
  - Match callee `"helper"` against `declarations` in the same file
  - If not found locally, search merged `ProjectCallGraph.declarations`

- [ ] Handle package-qualified names:
  ```go
  import "example.com/pkg"
  pkg.Func(x)          // callee is "pkg.Func"
  ```
  - Resolve `pkg` to import path → look up in project declarations or mark as external

- [ ] Handle method calls (heuristic — no type inference):
  ```go
  func (r *Receiver) Method() {}
  func caller(r *Receiver) {
      r.Method()       // callee is "Receiver.Method"
  }
  ```
  - Use `receiver_of_method_call()` from existing `classify.rs` to get receiver text
  - Approximate type by variable name heuristics or skip if type can't be determined

- [ ] **ponytail:** Skip external calls (stdlib, third-party) — no function summaries for code we don't own. Mark as opaque: taint flows through arguments but the callee is a source/sink/sanitizer black box.

---

## Phase 2: Function Summary Computation

### 2.1 Define `TaintSummary` struct

- [ ] Add to `src/lang/go/detectors/cwe/taint/model.rs`:
  ```rust
  /// Summary of a function's taint behavior for inter-procedural propagation.
  #[derive(Debug, Clone, Default)]
  pub struct TaintSummary {
      /// For each parameter index, whether it's a source of taint.
      /// None = parameter not analyzed (opaque).
      pub param_sources: Vec<Option<bool>>,
      /// For each return position (0 = single return, 0..n for multi-return),
      /// whether the return value carries taint from the parameters.
      pub return_sources: Vec<bool>,
      /// Parameter indices that are sanitized by which sanitizer kind.
      pub param_sanitizers: Vec<(usize, SanitizerKind)>,
      /// Whether this function unconditionally calls a sink (no params needed).
      pub has_direct_sink: bool,
      /// Sink kinds called within this function.
      pub sink_kinds: Vec<SinkKind>,
  }
  ```

- [ ] Add to `GoUnitFacts`:
  ```rust
  pub taint_summaries: HashMap<String, TaintSummary>,
  ```

### 2.2 Intra-procedural summary computation

- [ ] Create `compute_taint_summary(function_node: tree_sitter::Node, unit: &ParsedUnit, facts: &GoUnitFacts) -> TaintSummary`:
  - Extract the function body
  - Run the existing intra-procedural taint graph builder (reuse `build_taint_graph` and `extract_taint_facts`) **scoped to this one function**
  - For each parameter of the function:
    - Check if the parameter reaches a sink (via the existing BFS) → `param_sources[i] = true`
    - Check if the parameter goes through a sanitizer before reaching a sink → `param_sanitizers.push((i, sanitizer_kind))`
  - For each return statement in the function:
    - Check if any tainted variable reaches the return value → `return_sources[j] = true`
  - Check if any unguarded sink exists (sink reachable without any parameter) → `has_direct_sink = true`

- [ ] Handle parameter-to-parameter propagation:
  ```go
  func wrapper(x string) string {
      return x  // param 0 → return 0
  }
  ```

- [ ] Handle return-statement extraction:
  - Walk the function body for `return_statement` nodes
  - For each return value expression, run `referenced_identifiers` to find parameter references
  - If a return value references a tainted parameter, mark the corresponding return position as tainted

### 2.3 Summary caching

- [ ] Compute summaries lazily: only for functions that appear as callees in the call graph
- [ ] Cache in `GoUnitFacts.taint_summaries` after computation
- [ ] Invalidation strategy: invalidate summaries when the file's content hash changes (use existing `SourceIndex` or content-hash mechanism)
- [ ] Store summaries in the incremental cache (`target/slopguard-cache/`) alongside per-file findings

### 2.4 Builtin function summaries

- [ ] Add a table of hand-written summaries for common stdlib functions that don't have source/sink/sanitizer classification:
  ```rust
  lazy_static! {
      static ref BUILTIN_SUMMARIES: HashMap<&'static str, TaintSummary> = {
          let mut m = HashMap::new();
          // fmt.Sprintf(format, args...) — return is tainted if any arg is tainted
          m.insert("fmt.Sprintf", TaintSummary {
              param_sources: vec![None, Some(true), Some(true)], // varargs approximated
              return_sources: vec![true],
              ..Default::default()
          });
          // strings.Join(elems, sep) — return is tainted if elems are tainted
          m.insert("strings.Join", TaintSummary {
              param_sources: vec![Some(true), None],
              return_sources: vec![true],
              ..Default::default()
          });
          // bytes.Buffer.String() — return is tainted if buffer had tainted writes
          // (complex, skip for now — rely on intra-procedural tracking)
          m
      };
  }
  ```

- [ ] Cover the most common 20–30 propagation functions:
  - String manipulation: `strings.Join`, `strings.Replace`, `strings.Repeat`, `strings.Trim`, `strings.TrimSpace`, `fmt.Sprintf`, `fmt.Sprintf`, `fmt.Errorf`
  - Byte manipulation: `append`, `copy`, `json.Marshal`, `json.Unmarshal`
  - Path manipulation: `filepath.Join`, `filepath.Dir`, `path.Join`
  - Type conversion: `string()`, `[]byte()`, `strconv.Itoa` (sanitizer), `strconv.FormatInt`
  - Encoding: `base64.StdEncoding.EncodeToString`, `hex.EncodeToString`

---

## Phase 3: Cross-Function Propagation

### 3.1 Call-site wiring

- [ ] In `build_taint_graph()` (or a new `build_inter_procedural_graph()`), add cross-function edges:
  - For each `call_expression` where the callee has a `TaintSummary`:
    - **Source edge**: if `summary.return_sources[j]` is true, add an edge from the callee's summary → caller's result variable
    - **Sink edge**: if `summary.param_sources[i]` is true and argument `i` is tainted, add an edge from the argument → caller's sink node
    - **Sanitizer edge**: if `summary.param_sanitizers[i]` matches, mark the argument as sanitized

- [ ] Wire argument mapping:
  ```go
  func caller() {
      x := getInput()          // source
      y := sanitize(x)         // sanitizer call
      z := helper(y)           // cross-function call
      sink(z)                  // should be sanitized
  }

  func helper(s string) string {
      return s                 // TaintSummary: param 0 → return 0
  }
  ```
  - At the `helper(y)` call site: argument 0 is `y`, which is sanitized
  - Summary says: param 0 → return 0 (pass-through)
  - Result: `z` is sanitized → `sink(z)` does not fire

### 3.2 Inter-procedural graph merging

- [ ] Create `merge_taint_graphs(files: &[ParsedUnit]) -> TaintGraph`:
  - Build per-file `TaintGraph` instances (existing `build_taint_graph`)
  - Merge nodes and edges into a single graph
  - Resolve cross-file variable references using `decl_nodes` across files
  - For each cross-file call edge, add inter-procedural edges

- [ ] Handle the scope hierarchy for cross-file resolution:
  - Package-level scope is shared across all files in the same package
  - Function-level scope is per-file
  - Add `Package` scope kind to `ScopeKind`

### 3.3 Depth-limited BFS extension

- [ ] Extend `find_taint_paths()` to support inter-procedural edges:
  - The BFS can now traverse across function boundaries via `Return` nodes
  - Add a `max_depth` parameter (default: 10 hops)
  - Track visited function calls to prevent infinite loops

- [ ] Add `TaintNode::Return` creation in the graph builder:
  - When a function has a `return` statement that returns a tainted value, create a `Return` node
  - Wire the returned variable → `Return` node
  - At the call site, wire `Return` node → caller's result variable

- [ ] Update `TaintGraph` indexing:
  - Add `by_function: HashMap<String, Vec<TaintNodeId>>` to quickly find nodes within a function
  - Add `cross_file_edges: Vec<TaintEdge>` for edges spanning file boundaries

### 3.4 Fixed-point iteration

- [ ] Implement iterative propagation:
  ```rust
  fn propagate_inter_procedural(graph: &mut TaintGraph, max_iterations: usize) {
      for _ in 0..max_iterations {
          let mut changed = false;
          for edge in &graph.edges.clone() {
              // Propagate taint along inter-procedural edges
              if is_inter_procedural(edge) && propagate_taint(graph, edge) {
                  changed = true;
              }
          }
          if !changed { break; }
      }
  }
  ```
  - Default max iterations: 5
  - Stop early when no new edges are added (fixed point reached)

### 3.5 Integration with existing CWE detectors

- [ ] Update `GoCweScan::run()` to call `merge_taint_graphs()` and `propagate_inter_procedural()` when taint is enabled
- [ ] The merged graph replaces the per-file graph for CWE detection
- [ ] Fall back to per-file graph if the project-level merge fails or is disabled

---

## Phase 4: Evidence and Reporting

### 4.1 Multi-hop path display

- [ ] Extend `TaintSinkInfo` in `src/rules/evidence.rs` to include hop details:
  ```rust
  pub struct TaintSinkInfo {
      pub kind: String,
      pub function: String,
      /// Cross-function hops in the taint path (inter-procedural only)
      pub hops: Vec<TaintHop>,
  }

  pub struct TaintHop {
      pub function: String,      // function name at this hop
      pub kind: String,          // "source" | "sanitizer" | "call" | "return"
      pub variable: String,      // variable carrying taint at this hop
      pub file: String,          // file where this hop occurs
      pub line: usize,
  }
  ```

- [ ] When `--taint-show-paths` is set, populate `TaintSinkInfo.hops` with the full inter-procedural path

### 4.2 JSON reporter update

- [ ] In `src/reporting/json/entry.rs`: when `ctx.taint_show_paths` is true, serialize `TaintSinkInfo.hops` in the finding JSON under `evidence.sink.hops`

### 4.3 SARIF reporter update

- [ ] In `src/reporting/sarif/entry.rs`: when `ctx.taint_show_paths` is true, include hop information in the SARIF `properties` bag as `taintPath`

### 4.4 Text reporter update

- [ ] In `src/reporting/text/render.rs`: when `--taint-show-paths` is set, print the taint path:
  ```
  Taint path (4 hops):
    source: r.URL.Query().Get("name") at file.go:12
      → helper() at file.go:15 (param 0 → return 0)
      → transform() at file.go:18 (sanitized via filepath.Clean)
      → sink: os.Open(path) at file.go:21
  ```

### 4.5 Test for reporting

- [ ] Add test in `tests/reporting_json_finding.rs` verifying that a taint finding with `show_paths=true` includes hop details in JSON output

---

## Phase 5: Tests and Fixtures

### 5.1 Integration test file

- [ ] Create `tests/go_taint_integration.rs` with fixture-driven tests:
  ```rust
  #[test]
  fn inter_procedural_taint_flows() {
      // For each inter-procedural fixture pair:
      //   materialize vulnerable → assert finding
      //   materialize safe → assert NO finding
  }
  ```

- [ ] Create `tests/helpers/go_taint_cases.rs` fixture discovery helper (mirroring `go_perf_cases.rs` and `go_bp_cases.rs`)

### 5.2 Inter-procedural fixture pairs

Create fixture files in `tests/fixtures/go/taint/`:

- [ ] **Direct call chain (depth 2)** — `IP-001`:
  ```go
  // vulnerable: caller -> callee -> sink
  func caller() {
      x := r.URL.Query().Get("input")
      callee(x)
  }
  func callee(s string) {
      os.Open(s)  // should fire CWE-22
  }
  ```

- [ ] **Sanitized call chain** — `IP-002`:
  ```go
  // safe: caller -> sanitizer -> callee -> sink
  func caller() {
      x := r.URL.Query().Get("input")
      safe := filepath.Clean(x)
      callee(safe)
  }
  func callee(s string) {
      os.Open(s)  // should NOT fire (sanitized)
  }
  ```

- [ ] **Return propagation (depth 2)** — `IP-003`:
  ```go
  // vulnerable: caller -> callee returns tainted -> sink
  func caller() {
      x := getInput()
      os.Open(x)  // should fire CWE-22
  }
  func getInput() string {
      return r.URL.Query().Get("input")
  }
  ```

- [ ] **Depth 3 chain** — `IP-004`:
  ```go
  // vulnerable: funcA -> funcB -> funcC -> sink
  func funcA() {
      x := r.URL.Query().Get("input")
      funcB(x)
  }
  func funcB(s string) {
      funcC(s)
  }
  func funcC(s string) {
      os.Open(s)  // should fire CWE-22
  }
  ```

- [ ] **Method call chain** — `IP-005`:
  ```go
  // vulnerable: method call on struct receiver
  type Handler struct {}
  func (h *Handler) Serve() {
      path := r.URL.Query().Get("path")
      h.openFile(path)
  }
  func (h *Handler) openFile(p string) {
      os.Open(p)  // should fire CWE-22
  }
  ```

- [ ] **Sanitized in callee** — `IP-006`:
  ```go
  // safe: caller -> callee that sanitizes -> sink
  func caller() {
      x := r.URL.Query().Get("input")
      safe := callee(x)
      os.Open(safe)  // should NOT fire
  }
  func callee(s string) string {
      return filepath.Base(s)  // sanitizes
  }
  ```

- [ ] **Recursive chain** — `IP-007`:
  ```go
  // vulnerable: recursive call with tainted data
  func process(s string, depth int) {
      if depth > 5 { return }
      os.Open(s)  // should fire CWE-22
      process(s, depth + 1)
  }
  func caller() {
      process(r.URL.Query().Get("input"), 0)
  }
  ```

- [ ] **Closure capture** — `IP-008`:
  ```go
  // vulnerable: closure captures tainted variable
  func caller() {
      x := r.URL.Query().Get("input")
      fn := func() {
          os.Open(x)  // should fire CWE-22 (captured)
      }
      fn()
  }
  ```

- [ ] **Multiple returns** — `IP-009`:
  ```go
  // vulnerable: function returns (value, error), both tainted
  func caller() {
      path, _ := lookup()
      os.Open(path)  // should fire CWE-22
  }
  func lookup() (string, error) {
      return r.URL.Query().Get("input"), nil
  }
  ```

- [ ] **Go routine with taint** — `IP-010`:
  ```go
  // vulnerable: go func launches with tainted data
  func caller() {
      ch := make(chan string)
      go func() {
          s := <-ch
          os.Open(s)  // should fire CWE-22
      }()
      ch <- r.URL.Query().Get("input")
  }
  ```

### 5.3 Register fixtures

- [ ] Add all 10 fixture pairs (20 files) to `tests/fixtures/manifest.toml`
- [ ] Register in `go_taint_cases.rs` helper

### 5.4 Integration test wiring

- [ ] Add `go_taint_fixtures_fire_vulnerable_and_silence_safe` test to `tests/go_taint_integration.rs`
- [ ] Add `go_taint_fixture_inventory_is_sorted_and_contiguous` test

### 5.5 Smoke budget update

- [ ] Run `cargo test --test perf_regression` after inter-procedural changes
- [ ] Update `MAX_FULL_SCAN` / `MAX_COLLECT_AND_SCAN` in `tests/perf_regression.rs` if inter-procedural analysis adds measurable overhead
- [ ] Target: <20% regression from baseline (current baseline: ~4.4s/scan)

---

## Phase 6: Edge-Case Handling

### 6.1 Recursion

- [ ] Detect recursive calls in the call graph:
  - `funcA → funcB → funcA` (mutual recursion)
  - `funcA → funcA` (direct recursion)
- [ ] Cap recursion depth at 5 hops (configurable via `--max-taint-depth`)
- [ ] When a recursive cycle is detected, use the summary from the previous iteration (widening)
- [ ] Mark recursive paths with a `recursive: true` flag in evidence

### 6.2 Pointer / reference aliasing

- [ ] Handle `&x` passing:
  ```go
  func caller() {
      x := r.URL.Query().Get("input")
      mutate(&x)
      os.Open(x)  // x is now tainted
  }
  func mutate(p *string) {
      *p = externalSource()  // taints *p
  }
  ```
  - Track `&var` expressions in call arguments
  - If the callee writes to `*param`, propagate taint back to the caller's variable
  - **Heuristic:** only handle the common case where the callee assigns `*p = expr` — skip struct field mutations

### 6.3 Map / slice mutations

- [ ] Track map writes:
  ```go
  func caller() {
      m := make(map[string]string)
      m["key"] = r.URL.Query().Get("input")  // m["key"] is tainted
      val := m["key"]                          // val is tainted
      os.Open(val)                             // should fire CWE-22
  }
  ```
  - When `m[key] = value` is encountered, if `value` is tainted, mark the map variable as tainted
  - When `val := m[key]` reads from a tainted map, mark `val` as tainted
  - **ponytail:** per-key tracking is complex — track at the map variable level (all keys tainted if any key is tainted)

- [ ] Handle `append`:
  - `s = append(s, tainted)` → `s` is tainted
  - `s = append(s, safe)` → `s` is NOT tainted (if `s` was clean)

### 6.4 Deferred function calls

- [ ] Track `defer` targets:
  ```go
  func caller() {
      x := r.URL.Query().Get("input")
      defer func() {
          os.Open(x)  // should fire CWE-22
      }()
  }
  ```
  - When a `defer` statement encloses a function literal, analyze the deferred body
  - If the deferred body references a tainted variable from the enclosing scope, emit a finding
  - Wire the deferred closure into the call graph as a callee of the enclosing function

### 6.5 Goroutine closures

- [ ] Track `go func()` captures:
  ```go
  func caller() {
      x := r.URL.Query().Get("input")
      go func() {
          os.Open(x)  // should fire CWE-22 (captured at go-time)
      }()
  }
  ```
  - When `go func() { ... }()` is encountered, analyze the closure body
  - If the body references variables from the enclosing scope that are tainted, propagate taint into the goroutine
  - Wire the goroutine closure into the call graph with a `goroutine: true` flag

### 6.6 Interface dispatch

- [ ] **ponytail:** Interface dispatch is not supported in the initial implementation
  - When a method is called on an interface type, mark the call as opaque (no callee resolution)
  - Taint flows through the arguments but not through the return value
  - Document this limitation in `docs/taint.md`

---

## Dependencies

- **Phase 1–6**: Tree-sitter CST for call expression extraction (already available via existing parser)
- **Phase 2**: Existing `build_taint_graph()` and `extract_taint_facts()` (reused for per-function analysis)
- **Phase 3**: Existing `find_taint_paths()` BFS (extended for inter-procedural edges)
- **Phase 4**: Existing `--taint-show-paths` CLI flag (already parsed, needs wiring)
- **Phase 5**: Existing `tests/helpers/mod.rs` fixture helpers
- **Phase 6**: May overlap with P2.4 Category C PERF rules (PERF-134, 139) that also need call-graph infrastructure — coordinate implementation order

## Quick Reference

| Phase | Items | Effort | Dependencies | Risk |
|-------|-------|--------|-------------|------|
| 1 — Call graph | ~8 items | 5–7d | Tree-sitter CST | Low — straightforward AST extraction |
| 2 — Summaries | ~7 items | 4–5d | Phase 1 | Medium — summary correctness is critical |
| 3 — Propagation | ~8 items | 4–5d | Phase 2 | High — cross-file merging complexity |
| 4 — Reporting | ~5 items | 2–3d | Phase 3 | Low — UI-only changes |
| 5 — Tests | ~8 items | 3–4d | Phase 1–4 | Low — fixture-driven testing |
| 6 — Edge cases | ~10 items | 3–4d | Phase 3 | High — pointer/map/goroutine complexity |
