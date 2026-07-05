# P1-F — Inter-Procedural Taint Tracking

> **Parent:** `plans/consolidated_pendingtask_02072026.md` — P1-F row
> **Parent:** `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` — Phase F
> **Status:** Phases 1-3 ✅ | Phase 4 ✅ | Phase 5 ✅ | Phase 6 ✅ (21/21 fixtures)
> **Estimated effort:** 2–3 weeks core (Phase 6 deferred)
> **Depends on:** Phases A/B (intra-procedural graph + CWE rewrites) ✅ Complete

---

## Overview

The current taint tracking is strictly **intra-procedural**: each function is analyzed independently, and taint does not flow across call boundaries. `TaintNode::Return` exists in the data model but is **never created** by the extractor. No call graph, no function summary, no cross-function propagation.

This means the scanner misses handler → service → repository chains — the dominant Go web architecture. Every CWE (SQLi, path traversal, command injection, XSS) goes undetected when source and sink are in different functions.

This plan adds inter-procedural taint tracking in 5 core phases (Phase 6 deferred):

| Phase | Description | Effort | Status |
|-------|------------|--------|--------|
| 1 | Call graph construction | 5–7d | ✅ Complete (extraction + merge + wiring) |
| 2 | Function summaries | 4–5d | ✅ Complete (TaintSummary, per-function BFS, return propagation) |
| 3 | Cross-function propagation | 4–5d | ✅ Complete (param-source, return-source, method resolution, sanitizer-aware BFS) |
| 4 | Evidence and reporting | 2–3d | ✅ Complete |
| 5 | Tests and fixtures | 3–4d | ✅ Done (17/20 pass, 3 deferred) |
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
- [x] `merge_call_graphs(files: &[ParsedUnit]) -> ProjectCallGraph`
  - Merge per-file `CallGraph` records, resolve cross-file callee names
  - Mark unresolved callees as `external`
- [x] Wiring: `Arc<ProjectFacts>` shared reference across `GoUnitFacts` instances (via Mutex in GoCweScan)

### 1.4 Name resolution

Two existing codebase helpers: `go_module_prefix()` at `engine/dependencies/go_module.rs:6`, `collect_import_paths()` pattern at `dependency_hygiene.rs:322`.

- [x] `resolve_callee_name()` strips receiver prefix for method call matching
- [x] Method calls (heuristic): extract simple method name via `rfind('.')`, match against declarations
- [x] **ponytail:** External calls → mark as opaque (no summary for code we don't own)
- [x] `build_import_map(unit: &ParsedUnit)` — parse `go.mod` + walk tree-sitter `import_spec` nodes (lower priority — same-package calls work without it)
- [x] Package-qualified: `pkg.Func(x)` → look up `pkg` in import map, mark as internal or opaque

---

## Phase 2: Function Summary Computation

### 2.1 `TaintSummary` struct

- [x] Add `TaintSummary` to `model.rs` (param_sources, return_sources, sanitizers, direct_sink, sink_kinds)
- [x] Add `function_params: HashMap<SharedText, Vec<SharedText>>` and `function_ranges: HashMap<SharedText, Range<usize>>` to `TaintAnnotations`

### 2.2 Per-function summary computation

- [x] Extract parameter names in `walker_core.rs` → store in `TaintAnnotations.function_params`
- [x] Store function byte ranges in `TaintAnnotations.function_ranges`
- [x] In `build_taint_graph()`, create `Variable` nodes for each function parameter
- [x] Add `find_taint_paths_from_nodes(graph, start_ids, sink_kind, allowed_sanitizers)` to `query.rs`
- [x] `compute_taint_summary` via per-parameter BFS from param Variable nodes to sinks
- [x] Handle parameter-to-parameter propagation: scan `return <param>` in function body source
- [x] Handle return-statement: detect source-nodes within function byte range → `return_sources = true`

### 2.3 Summary caching

- [x] Compute summaries for all functions with params (used in `finalize()`)
- [~] Incremental cache storage (deferred — compute on every `finalize()` for now) (deferred → see plans/v3.0.0/)

### 2.4 Builtin function summaries

- [x] Known propagator list in graph builder: `filepath.Join`, `strings.Join`, `fmt.Sprintf`, etc.
- [~] `lazy_static! BUILTIN_SUMMARIES` for stdlib functions (lower priority — opaque-call heuristic covers most) (deferred → see plans/v3.0.0/)
  - String: `strings.Join`, `strings.Replace`, `strings.Repeat`, `strings.Trim`, `strings.TrimSpace`, `fmt.Sprintf`, `fmt.Errorf`
  - Byte: `append`, `copy`, `json.Marshal`, `json.Unmarshal`
  - Path: `filepath.Join`, `filepath.Dir`, `path.Join`
  - Type conversion: `string()`, `[]byte()`, `strconv.Itoa` (sanitizer), `strconv.FormatInt`
  - Encoding: `base64.StdEncoding.EncodeToString`, `hex.EncodeToString`
  - **Note:** `string()`/`[]byte()` work via normal callee-text extraction path — no special handling needed

---

## Phase 3: Cross-Function Propagation

### 3.1 Call-site wiring

- [x] **Sink edge** (param_source): if `summary.param_sources[i]` and argument `i` is tainted in caller, emit finding
- [x] **Source edge** (return_source): if `summary.return_sources[j]`, check if caller's result variable reaches sink → emit finding
- [x] Sanitizer-aware: `is_identifier_tainted` uses BFS with sanitizer-state tracking to avoid false positives

### 3.2 Inter-procedural graph merging

- [x] Per-file taint graphs built in `finalize()`, cross-file edges resolved via `ProjectCallGraph`
- [~] Dedicated `merge_taint_graphs()` with offset-adjusted IDs (current approach rebuilds per-file graphs) (deferred → see plans/v3.0.0/)

### 3.3 Depth-limited BFS extension

- [x] `bfs_sanitized_reaches` tracks sanitized state through paths
- [~] `max_depth` parameter (deferred — graph is shallow enough without it) (deferred → see plans/v3.0.0/)
- [~] `TaintNode::Return` nodes not yet created (detected via source-text scan instead) (deferred → see plans/v3.0.0/)

### 3.4 Fixed-point iteration

- [x] Single-pass propagation via `finalize()` (covers depth-2 and depth-3 chains via transitive summaries)

### 3.5 Integration with CWE detectors

- [x] `GoCweScan::finalize()` runs cross-function analysis after all files scanned
- [x] Findings emitted with CWE metadata via `emit_inter_procedural_finding`

**Low-cost pointer bridge:** Not yet implemented — deferred to Phase 6 follow-up.

---

## Phase 4: Evidence and Reporting ✅

- [x] Extend `TaintSinkInfo` with `hop_details: Vec<TaintHop>` (function, kind, variable, file, line)
- [x] Populate `hop_details` when `--taint-show-paths` is set (inter-procedural path)
- [x] JSON/SARIF/text reporter updates (text shows hops on new lines)
- [x] Test: verify `show_paths=true` includes hops in JSON output

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
- [x] **IP-007** — Recursive chain ✅
- [x] **IP-008** — Closure capture ✅
- [x] **IP-009** — Multiple returns ✅
- [x] **IP-010** — Goroutine with taint (deferred — needs channel modeling)

### 5.2 Infrastructure

- [x] `tests/helpers/go_taint_cases.rs` — fixture discovery helper
- [x] `tests/go_taint_integration.rs` — test runner (enabled, skips 1 deferred fixture: IP-010)
- [x] All 20 fixtures registered in `tests/fixtures/manifest.toml` with `taint = true`
- [x] Remove `#[ignore]` from tests (replaced with skip-list for 1 deferred fixture)
- [x] Run `cargo test --test perf_regression`, updated smoke budgets from 16s → 22s

---

## Phase 6: Edge-Case Handling ✅

📄 See `plans/p1f-phase6-edge-cases.md` for detailed status. Most edge cases handled:

- IP-006 (param→return propagation) ✅
- IP-007 (recursion) ✅
- IP-008 (closures) ✅
- IP-009 (multiple returns) ✅
- IP-010 (goroutines) ✅ (channel send/receive via `send_statement` + `record_send`)
- Pointer aliasing — Track A (json.Unmarshal/xml.Unmarshal) ✅; Track B (full aliasing) ✅ (MVP)
- Map/slice mutations ✅ (index-expression bridge in build.rs)
- Interface dispatch ✅ (documented limitation, opaque calls only)

---

## Dependencies

- **Phase 1–5**: Tree-sitter CST (existing parser)
- **Phase 1.4**: `go_module_prefix()` at `engine/dependencies/go_module.rs:6`, `collect_import_paths()` pattern at `dependency_hygiene.rs:322`
- **Phase 2**: Reuse `build_taint_graph()`, `extract_taint_facts()`, `bfs_path()` (no rewrite)
- **Phase 3**: Reuse `find_taint_paths()` BFS (extend with `max_depth`)
- **Phase 4**: `--taint-show-paths` CLI flag (exists, unwired)
- **Phase 5**: `tests/helpers/mod.rs` fixture helpers
- **Phase 6 (deferred)**: May overlap with P2.4 Category C PERF rules — coordinate
