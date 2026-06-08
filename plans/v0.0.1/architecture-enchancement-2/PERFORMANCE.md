# Plan 1: Performance — Tree Walk Unification & Hot-Path Optimization

> **Priority:** Critical (blocks 2-3× fact-extraction speedup)

## Background

Currently each Go file endures **up to 12 tree traversals**:
- 1: `attach_function_context` → collect_function_spans  
- 2: CWE `build_go_unit_facts` → walk_calls_and_assignments
- 3: PERF `build_go_perf_facts` → walk_calls_and_assignments
- 4: PERF `build_go_perf_facts` → walk_nodes(var_spec)
- 5-12: Eight individual detectors call `walk_nodes` independently

All walk the same tree. Fusing to 1 traversal would deliver **2-3× fact-extraction speedup**.

## Checklist

### Phase 1: Fuse fact extraction walks

- [x] **1.1** Create `src/lang/go/detectors/facts.rs` with a unified `GoFacts` struct containing both `GoCweFacts` and `GoPerfFacts`
- [x] **1.2** Create `pub(crate) fn build_go_facts(root: Node) -> GoFacts` that does ONE `walk_calls_and_assignments` traversal populating both CWE and PERF facts simultaneously
- [x] **1.3** Add `Vec<FunctionSpan>` collection inside the unified walk using the existing `try_record_function_span` hook (`ast/function.rs:98`)
- [x] **1.4** Store the collected `function_spans` on `ParsedUnit` so `attach_function_context` can skip the tree walk
- [x] **1.5** Add new fact vectors to `GoPerfFacts` to eliminate individual detector walks:
  - `defer_starts: Vec<usize>` — byte offsets of defer statements
  - `go_starts: Vec<usize>` — byte offsets of go statements  
  - `for_nodes: Vec<(usize, usize)>` — byte ranges of for statements
  - `type_assertions: Vec<usize>` — byte offsets of type assertions
- [x] **1.6** Collect these during the unified walk (arm for `defer_statement`, `go_statement`, `for_statement`, `type_assertion_expression`)
- [x] **1.7** Rewrite the 8 detectors that currently call `walk_nodes` to iterate the precomputed fact vectors instead:
  - [x] `loop_allocations.rs:218` — PERF-7 (defer)
  - [x] `parsing_in_loops.rs:314` — PERF-16 (composite_literal)
  - [x] `concurrency_and_path.rs:32` — PERF-29 (go_statement)
  - [x] `concurrency_and_path.rs:106` — PERF-31 (defer)
  - [x] `concurrency_and_path.rs:197` — PERF-39 (for_statement)
  - [x] `concurrency_and_path.rs:300` — PERF-43 (defer)
  - [x] `concurrency_and_path.rs:333` — PERF-44 (type_assertion)
  - [x] `observability.rs:205` — PERF-100 (call_expression)
- [x] **1.8** Update `engine/walk.rs:scan_entry` to call the unified `build_go_facts` instead of separate CWE + PERF builders
- [x] **1.9** Remove the separate tree walk from `attach_function_context` when `ParsedUnit.function_spans` is precomputed

### Phase 2: SourceIndex → phf::Map + u64 bitmask

- [x] **2.1** Rewrite `src/lang/go/detectors/cwe/source_index.rs`:
  - Replace `NEEDLES: &[&str]` with `static NEEDLE_MAP: phf::Map<&'static str, u64>`
  - Replace `flags: Vec<bool>` with `flags: u64`
  - `has()`: use `NEEDLE_MAP.get(needle)` + bitmask AND — O(1)
  - `build()`: iterate `NEEDLE_MAP.entries()` instead of `NEEDLES.iter()`
- [x] **2.2** Same for `src/lang/go/detectors/perf/source_index.rs`
- [x] **2.3** Verify all callers still compile (the public API shape doesn't change)

### Phase 3: SourceIndex::build() → Aho-Corasick

- [x] **3.1** Replace `source.contains(needle)` ×39/51 with a single Aho-Corasick pass
- [x] **3.2** Build an `AhoCorasick` automaton once at startup (static/LazyLock) from all needles
- [x] **3.3** `SourceIndex::build()` runs `automaton.find_iter(source)` once → populates bitmask

### Phase 4: Callee index for O(1) rule dispatch

- [x] **4.1** Add `calls_by_callee: HashMap<SharedText, Vec<usize>>` to both `GoCweFacts` and `GoPerfFacts`
- [x] **4.2** Populate during fact extraction (group call indices by SharedText callee name)
- [x] **4.3** Update detectors that iterate all calls to use `facts.calls_by_callee.get("target_callee")` instead
- [x] **4.4** This eliminates O(all_calls) loops in ~25 detectors

### Phase 5: Hot-path allocation reduction

- [x] **5.1** Replace per-file `HashMap` interner (`SharedTextInterner`) with `thread_local!` HashMap that persists across files within a worker thread
- [x] **5.2** Use `LazyLock<HashMap<&'static str, Arc<str>>>` for known callee strings that are compile-time constants
- [x] **5.3** Replace `Vec<bool>` in SourceIndex with u64 (Phase 2 covers this)
- [x] **5.4** Eliminate `is_flag_call` `format!` by precomputing flag method suffixes as a const array
- [x] **5.5** Replace `depth_stack: Vec<usize>` in `ast/function.rs:walk()` with implicit depth tracking from TreeCursor

## Verification

- [x] `cargo bench --bench scan_throughput` shows measurable improvement (>20% on `scan_materialized_fixtures`)
- [x] All 275 detectors produce identical findings before/after
- [x] `make lint` passes
