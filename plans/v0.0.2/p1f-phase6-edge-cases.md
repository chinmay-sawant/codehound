# P1-F Phase 6 — Edge-Case Handling (Follow-up)

> **Parent:** `plans/p1f-inter-procedural-taint.md` — Phase 6 (deferred)
> **Status:** All items done. 21/21 fixtures active.
> **Estimated effort:** 3–4 days
> **Depends on:** Phase 3 (cross-function propagation) ✅ Complete

---

## Overview

Edge cases deferred from the core inter-procedural taint plan. These are separable features that don't block the core value (direct chains, return propagation, sanitized chains, method calls — IP-001 through IP-006). Each is high-risk due to complexity in type inference, AST pattern matching, or concurrency semantics.

Phases 1-3 of P1-F must be complete before starting this work.

---

## Phase 6.1: Recursion — IP-007 ✅

### Fixture

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

### Checklist

- [x] Works without explicit recursion handling — `process` has a direct param→sink path, so `param_sources[0] = true` is computed from the direct `os.Open(s)` call. The recursive self-call is opaque, but the direct path is sufficient.
- [x] Enable IP-007 in `tests/go_taint_integration.rs`
- [~] **ponytail:** Depth cap, widening, and `recursive: true` evidence flag skipped — the direct param→sink path handles the common case. Add if mutual recursion causes issues. (deferred → see plans/v0.0.3/)

---

## Phase 6.2: Pointer / Reference Aliasing

Without type inference, full pointer tracking is hard. Two tracks:

### Track A: Deserialization output args (low-cost bridge) ✅

Added `tainted_output_args()` returning `[0]` for `json.Unmarshal` and
`xml.Unmarshal`. In the graph builder, after creating the sink node,
assignment edges are added from input argument variables to the output
pointer variable so taint flows through the deserialized result.

`decoder.Decode(&target)` deferred — the receiver-based taint origin needs
type inference.

### Track B: Full pointer aliasing ✅ (MVP done, future items deferred)

```go
func caller() {
    x := r.URL.Query().Get("input")
    mutate(&x)
    os.Open(x)
}
func mutate(p *string) {
    *p = externalSource()
}
```

- [x] Track `&var` expression in call arguments (strip `&` prefix)
- [x] `TaintSummary.output_pointer_params` — params with `*param = source()` patterns
- [x] In `finalize()`: for `&var` at output pointer positions, check if `var` reaches a sink
- [x] IP-011 fixture added (21/21 fixtures active)
- [~] **Future:** struct field mutations (`(*p).field = source()`) — deferred (deferred → see plans/v0.0.3/)
- [~] **Future:** `*p = tainted_var` (callee writes a tainted variable, not a direct source call) — needs RHS taint detection (deferred → see plans/v0.0.3/)

---

## Phase 6.3: Map / Slice Mutations ✅

### Map writes

```go
func caller() {
    m := make(map[string]string)
    m["key"] = r.URL.Query().Get("input")  // m is now tainted
    val := m["key"]                          // val is tainted
    os.Open(val)                             // CWE-22
}
```

- [x] Map writes (`m["key"] = tainted`) bridge taint back to the base map
      variable `m` via the index-expression bridge in `build.rs`.
- [x] Reads (`val := m["key"]`) resolve `m["key"]`'s identifiers including `m`,
      picking up the assignment edge from the bridge above.
- [x] **ponytail:** Per-map-variable granularity (any tainted key → variable tainted).

### Slice append

- [x] `append` is a known propagator (`append(s, tainted)` → result is tainted).
- [x] `s = append(s, safe)` — already handled: if `s` was clean, no edge from
      safe to the result (no source path).

---

## Phase 6.4: Deferred Function Calls ✅

```go
func caller() {
    x := r.URL.Query().Get("input")
    defer func() {
        os.Open(x)  // should fire CWE-22
    }()
}
```

- [x] Works via the same intra-procedural mechanism as closures (IP-008).
      The `defer func_literal` body shares the same taint graph as the
      enclosing function, so captured variables resolve correctly.
- [x] No call-graph wiring needed for the deferred function — intra-procedural
      analysis handles the taint source→sink path within the single file.

---

## Phase 6.5: Goroutine Closures — IP-010 ✅

```go
func caller() {
    ch := make(chan string)
    go func() {
        s := <-ch
        os.Open(s)  // should fire CWE-22
    }()
    ch <- r.URL.Query().Get("input")
}
```

- [x] `send_statement` handling: `walk_node` matches `"send_statement"` →
      `record_send` creates an `AssignmentDetail` bridging channel to value.
- [x] Source calls in send values: `result_variable_of_call` accepts
      `"send_statement"` → returns channel name as result variable.
- [x] Variable sends (`ch <- x`): handled by assignment edge loop
      (`referenced_identifiers("x")` → edge from `x` to `ch`).
- [x] 20/20 fixtures active. IP-010 removed from `DEFERRED` list.

---

## Phase 6.6: Additional Deferred Fixtures ✅

### Closure capture — IP-008 ✅

```go
func caller() {
    x := r.URL.Query().Get("input")
    fn := func() {
        os.Open(x)
    }
    fn()
}
```

- [x] Works via intra-procedural analysis — closure body shares the same taint graph as the enclosing function, so `x` → `os.Open(x)` is resolved within the single file's graph.
- [x] Fixture files created (IP-008-vulnerable.txt and IP-008-safe.txt exist)
- [x] Enable IP-008 in test runner

### Multiple returns — IP-009 ✅

```go
func caller() {
    path, _ := lookup()
    os.Open(path)
}
func lookup() (string, error) {
    return r.URL.Query().Get("input"), nil
}
```

- [x] Fixture files created (IP-009-vulnerable.txt and IP-009-safe.txt exist)
- [x] Handle multi-return taint propagation — `result_variable_of_call` updated to accept `ret_idx` and parse comma-separated LHS
- [x] Enable IP-009 in test runner

---

## Phase 6.7: Interface Dispatch ✅

- [x] **ponytail:** Interface dispatch is documented as a known limitation in
      `documents/taint.md`. Methods called on interface types are treated as opaque
      — taint flows through arguments but return values are not tracked.

---

## Dependencies

- `plans/p1f-inter-procedural-taint.md` Phases 1-3 complete (call graph + summaries + propagation)
- Tree-sitter CST (existing)
- No new external dependencies

## Quick Reference

| Item | Effort | Risk | Blocks others? |
|------|--------|------|---------------|
| 6.1 Recursion | 0.5d | Medium | No |
| 6.2 Track A (pointer bridge) | 0.5d | Low | No |
| 6.2 Track B (full aliasing) | 1.5d | High | No |
| 6.3 Map/slice | 0.5d | Medium | No |
| 6.4 Deferred calls | 0.5d | Medium | No |
| 6.5 Goroutines | 0.5d | Medium | No |
| 6.6 Closures + multi-return | 0.5d | Medium | No |
| 6.7 Interface dispatch | 0.25d | Low | No |
