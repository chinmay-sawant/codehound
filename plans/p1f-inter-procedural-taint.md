# P1-F — Inter-Procedural Taint Tracking

> **Parent:** `plans/consolidated_pendingtask_02072026.md` — P1-F row
> **Parent:** `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` — Phase F
> **Status:** Phase 1 (struct + extraction) ✅ | Phase 5 (fixtures + tests) ✅ | Rest pending
> **Estimated effort:** 2–3 weeks core (Phase 6 deferred)
> **Depends on:** Phases A/B (intra-procedural graph + CWE rewrites) ✅ Complete

---

## Overview

The current taint tracking is strictly **intra-procedural**: each function is analyzed independently, and taint does not flow across call boundaries. `TaintNode::Return` exists in the data model but is **never created** by the extractor. No call graph, no function summary, no cross-function propagation.

This means the scanner misses handler → service → repository chains — the dominant Go web architecture. Every CWE (SQLi, path traversal, command injection, XSS) goes undetected when source and sink are in different functions.

This plan adds inter-procedural taint tracking in 5 core phases (Phase 6 deferred):

| Phase | Description | Effort | Status |
|-------|------------|--------|--------|
| 1 | Call graph construction | 5–7d | ✅ Partial (struct + extraction done) |
| 2 | Function summaries | 4–5d | ☐ |
| 3 | Cross-function propagation | 4–5d | ☐ |
| 4 | Evidence and reporting | 2–3d | ☐ |
| 5 | Tests and fixtures | 3–4d | ✅ Done |
| 6 | Edge cases (deferred) | — | 📄 `plans/p1f-phase6-edge-cases.md` |

---

## Phase 1: Call Graph Construction

### 1.1 Data model

Design: flat `Vec<CallSite>` + pre-built `by_caller`/`by_callee` HashMap indexes (same pattern as `TaintGraph`).

- [x] Define `CallGraph`, `CallSite`, `FunctionDecl` in `src/lang/go/detectors/cwe/taint/model.rs`
- [x] Define `ProjectCallGraph` in same file
- [x] Add `call_graph: Option<CallGraph>` field to `GoUnitFacts` in `facts/types.rs`

### 1.2 Per-file call graph extraction

- [x] Create `extract/call_graph.rs` with `extract_call_graph(unit: &ParsedUnit) -> CallGraph`
  - Walks all `call_expression` nodes via tree-sitter CST
  - Extracts callee name, caller name (enclosing function), byte range, arguments, method/closure flags
- [x] Register function declarations (`function_declaration` → `FunctionDecl`)
- [x] Register method declarations (`method_declaration` → `FunctionDecl` with receiver)
- [x] Wire into `build_go_unit_facts()` in `facts/build.rs` (runs unconditionally)

### 1.3 Project-level call graph merge

- [x] `ProjectCallGraph` struct defined in `model.rs`
- [ ] `merge_call_graphs(files: &[ParsedUnit]) -> ProjectCallGraph`
  - Merge per-file `CallGraph` records, resolve cross-file callee names
  - Mark unresolved callees as `external`
- [ ] Wiring: `Arc<ProjectFacts>` shared reference across `GoUnitFacts` instances

### 1.4 Name resolution

Two existing codebase helpers: `go_module_prefix()` at `engine/dependencies/go_module.rs:6`, `collect_import_paths()` pattern at `dependency_hygiene.rs:322`.

- [ ] `build_import_map(unit: &ParsedUnit)` — parse `go.mod` + walk tree-sitter `import_spec` nodes
  - Classify each import as `internal` (starts with module prefix) or `external`
- [ ] Local name resolution: match `helper(x)` against file-level `declarations`
- [ ] Package-qualified: `pkg.Func(x)` → look up `pkg` in import map, mark as internal or opaque
- [ ] Method calls (heuristic): use `receiver_of_method_call()` from `classify.rs`, approximate type
- [ ] **ponytail:** External calls → mark as opaque (no summary for code we don't own)

---

## Phase 2: Function Summary Computation

### 2.1 `TaintSummary` struct

- [ ] Add `TaintSummary` to `model.rs`:
  ```rust
  pub struct TaintSummary {
      pub param_sources: Vec<Option<bool>>,
      pub return_sources: Vec<bool>,
      pub param_sanitizers: Vec<(usize, SanitizerKind)>,
      pub has_direct_sink: bool,
      pub sink_kinds: Vec<SinkKind>,
  }
  ```
- [ ] Add `taint_summaries: HashMap<String, TaintSummary>` to `GoUnitFacts`

### 2.2 Per-function summary computation

The existing `bfs_path()` already accepts arbitrary `source_ids` — it's the entry point that's restricted to `by_source`. Two subtasks:

- [ ] Extract parameter names in `walker_core.rs` → store in `TaintAnnotations.function_params`
- [ ] In `build_taint_graph()`, create `Variable` nodes for each function parameter
- [ ] Add `find_taint_paths_from_nodes(graph, start_ids, sink_kind, allowed_sanitizers)` to `query.rs`
- [ ] `compute_taint_summary(function_node, unit, facts) -> TaintSummary`:
  - Scoped intra-procedural graph → per-parameter BFS via `find_taint_paths_from_nodes`
  - Check `param_sources[i]`, `param_sanitizers`, `return_sources[j]`, `has_direct_sink`
- [ ] Handle parameter-to-parameter propagation (`return x` → param 0 → return 0)
- [ ] Handle return-statement extraction: walk `return_statement` nodes, find parameter references

### 2.3 Summary caching

- [ ] Compute lazily: only for functions that appear as callees in call graph
- [ ] Cache in `GoUnitFacts.taint_summaries` after computation
- [ ] Invalidate on file content hash change (use `SourceIndex` or content-hash mechanism)
- [ ] Store in incremental cache (`target/slopguard-cache/`)

### 2.4 Builtin function summaries

- [ ] `lazy_static! BUILTIN_SUMMARIES: HashMap<&'static str, TaintSummary>` with entries for:
  - String: `strings.Join`, `strings.Replace`, `strings.Repeat`, `strings.Trim`, `strings.TrimSpace`, `fmt.Sprintf`, `fmt.Errorf`
  - Byte: `append`, `copy`, `json.Marshal`, `json.Unmarshal`
  - Path: `filepath.Join`, `filepath.Dir`, `path.Join`
  - Type conversion: `string()`, `[]byte()`, `strconv.Itoa` (sanitizer), `strconv.FormatInt`
  - Encoding: `base64.StdEncoding.EncodeToString`, `hex.EncodeToString`
  - **Note:** `string()`/`[]byte()` work via normal callee-text extraction path — no special handling needed

---

## Phase 3: Cross-Function Propagation

### 3.1 Call-site wiring

- [ ] In `build_taint_graph()` or `build_inter_procedural_graph()`, for each `call_expression` with a known `TaintSummary`:
  - **Source edge**: if `summary.return_sources[j]`, edge from callee summary → caller result variable
  - **Sink edge**: if `summary.param_sources[i]` and argument `i` is tainted, edge from argument → sink node
  - **Sanitizer edge**: if `summary.param_sanitizers[i]` matches, mark argument as sanitized
- [ ] Wire argument mapping: map caller argument `i` to callee parameter `i` via `TaintSummary`

### 3.2 Inter-procedural graph merging

- [ ] `merge_taint_graphs(files: &[ParsedUnit]) -> TaintGraph`
  - Build per-file `TaintGraph` instances, merge nodes/edges/indexes with offset-adjusted `TaintNodeId`s
  - Resolve cross-file variable references, add inter-procedural edges
- [ ] Handle scope hierarchy: add `Package` scope kind to `ScopeKind`

### 3.3 Depth-limited BFS extension

- [ ] Extend `find_taint_paths()` with `max_depth` parameter (default: 10 hops)
- [ ] Track visited function calls to prevent infinite loops
- [ ] Create `TaintNode::Return` nodes in graph builder for tainted return values
  - Wire returned variable → `Return` node, then `Return` node → caller's result variable
- [ ] **ponytail:** Skip `cross_file_edges` and `by_function` fields — no consumer needs them. BFS follows all edges flatly.

### 3.4 Fixed-point iteration

- [ ] `propagate_inter_procedural(graph, max_iterations=5)`
  - Iterate all edges, propagate taint along inter-procedural edges, stop when no change
  - 5 iterations covers typical 2-3 hop chains; cycles converge within cap
  - ~20 lines, handles cycles for free (no SCC detection needed)

### 3.5 Integration with CWE detectors

- [ ] Update `GoCweScan::run()` to call `merge_taint_graphs()` and `propagate_inter_procedural()` when taint enabled
- [ ] Merged graph replaces per-file graph for detection (fallback to per-file on merge failure)

**Low-cost pointer bridge:** Add `tainted_output_args()` table for `json.Unmarshal`/`xml.Unmarshal`/`*.Decode` (~25 lines). Marks output pointer arguments as tainted after the call. Full pointer aliasing deferred to Phase 6 follow-up.

---

## Phase 4: Evidence and Reporting

- [ ] Extend `TaintSinkInfo` in `src/rules/evidence.rs` with `hops: Vec<TaintHop>` (function, kind, variable, file, line)
- [ ] Populate `hops` when `--taint-show-paths` is set
- [ ] JSON reporter: serialize `hops` in finding JSON under `evidence.sink.hops`
- [ ] SARIF reporter: include hop info in `properties.taintPath`
- [ ] Text reporter: print multi-hop path (source → call → return → sink with line numbers)
- [ ] Test: verify `show_paths=true` includes hops in JSON output

---

## Phase 5: Tests and Fixtures ✅

**Fixtures written Day 1 — zero implementation dependencies.**

### 5.1 Fixture files (20 files in `tests/fixtures/go/taint/`)

- [x] **IP-001** — Direct call chain (depth 2, vulnerable + safe)
- [x] **IP-002** — Sanitized call chain (safe: caller sanitizes before cross-function call)
- [x] **IP-003** — Return propagation (vulnerable: callee returns tainted data)
- [x] **IP-004** — Depth 3 chain (funcA → funcB → funcC → sink)
- [x] **IP-005** — Method call chain (struct receiver method calls helper method)
- [x] **IP-006** — Sanitized in callee (safe: callee applies filepath.Base)
- [x] **IP-007** — Recursive chain (deferred — Phase 6 follow-up)
- [x] **IP-008** — Closure capture (deferred)
- [x] **IP-009** — Multiple returns (deferred)
- [x] **IP-010** — Goroutine with taint (deferred)

### 5.2 Infrastructure

- [x] `tests/helpers/go_taint_cases.rs` — fixture discovery helper
- [x] `tests/go_taint_integration.rs` — test runner with `#[ignore]` (enable after Phase 3)
- [x] All 20 fixtures registered in `tests/fixtures/manifest.toml` with `taint = true`
- [ ] Remove `#[ignore]` from tests after Phase 3 is verified
- [ ] Run `cargo test --test perf_regression`, update smoke budgets if needed (<20% regression from ~4.4s baseline)

---

## Phase 6: Edge-Case Handling (Deferred)

📄 Moved to `plans/p1f-phase6-edge-cases.md`. Core value (direct chains, return propagation, sanitized chains, method calls — IP-001 through IP-006) ships without these. Estimated 3–4d of high-risk work.

Deferred items: IP-007 (recursion), IP-008 (closures), IP-009 (multiple returns), IP-010 (goroutines), pointer aliasing, map/slice mutations, interface dispatch.

---

## Dependencies

- **Phase 1–5**: Tree-sitter CST (existing parser)
- **Phase 1.4**: `go_module_prefix()` at `engine/dependencies/go_module.rs:6`, `collect_import_paths()` pattern at `dependency_hygiene.rs:322`
- **Phase 2**: Reuse `build_taint_graph()`, `extract_taint_facts()`, `bfs_path()` (no rewrite)
- **Phase 3**: Reuse `find_taint_paths()` BFS (extend with `max_depth`)
- **Phase 4**: `--taint-show-paths` CLI flag (exists, unwired)
- **Phase 5**: `tests/helpers/mod.rs` fixture helpers
- **Phase 6 (deferred)**: May overlap with P2.4 Category C PERF rules — coordinate
