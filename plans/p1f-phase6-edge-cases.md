# P1-F Phase 6 — Edge-Case Handling (Follow-up)

> **Parent:** `plans/p1f-inter-procedural-taint.md` — Phase 6 (deferred)
> **Status:** Fixture files exist (written Day 1 of P1-F). Core Phases 1-3 ✅. Implementation not started.
> **Estimated effort:** 3–4 days
> **Depends on:** Phase 3 (cross-function propagation) ✅ Complete

---

## Overview

Edge cases deferred from the core inter-procedural taint plan. These are separable features that don't block the core value (direct chains, return propagation, sanitized chains, method calls — IP-001 through IP-006). Each is high-risk due to complexity in type inference, AST pattern matching, or concurrency semantics.

Phases 1-3 of P1-F must be complete before starting this work.

---

## Phase 6.1: Recursion — IP-007

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

- [ ] Detect recursive calls in call graph (direct: `A→A`, mutual: `A→B→A`)
- [ ] Cap recursion depth at 5 hops (configurable via `--max-taint-depth`)
- [ ] When recursive cycle detected, use summary from previous iteration (widening)
- [ ] Mark recursive paths with `recursive: true` flag in evidence
- [x] Fixture files created (IP-007-vulnerable.txt and IP-007-safe.txt exist)
- [ ] Enable IP-007 in `tests/go_taint_integration.rs`

---

## Phase 6.2: Pointer / Reference Aliasing

Without type inference, full pointer tracking is hard. Two tracks:

### Track A: Deserialization output args (low-cost bridge, ~25 lines)

Already listed in Phase 3 of the main plan. Add a hardcoded table:

```go
json.Unmarshal(data, &target)  // arg 1 receives tainted data
xml.Unmarshal(data, &target)   // arg 1 receives tainted data
decoder.Decode(&target)        // arg 0 (receiver) writes to its arg
```

- [ ] Add `tainted_output_args(func_text: &str) -> &[usize]` to `classify.rs`
- [ ] In `build.rs`, after creating a sink node, wire tainted output args as variable nodes

### Track B: Full pointer aliasing (deferred)

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

- [ ] Track `&var` expressions in call arguments
- [ ] If callee writes `*p = expr`, propagate taint back to caller's variable
- [ ] **Heuristic:** only handle common case (`*p = expr`), skip struct field mutations
- [ ] Requires basic type inference: detect `*T` parameter patterns in callee declarations

---

## Phase 6.3: Map / Slice Mutations

### Map writes

```go
func caller() {
    m := make(map[string]string)
    m["key"] = r.URL.Query().Get("input")  // m is now tainted
    val := m["key"]                          // val is tainted
    os.Open(val)                             // CWE-22
}
```

- [ ] When `m[key] = value` and `value` is tainted, mark map variable as tainted
- [ ] When `val := m[key]` reads from tainted map, mark `val` as tainted
- [ ] **ponytail:** Per-key tracking is complex — track at map variable level (any tainted key → all keys tainted)

### Slice append

- [ ] `s = append(s, tainted)` → `s` is tainted
- [ ] `s = append(s, safe)` → `s` NOT tainted (if `s` was clean)

---

## Phase 6.4: Deferred Function Calls

```go
func caller() {
    x := r.URL.Query().Get("input")
    defer func() {
        os.Open(x)  // should fire CWE-22
    }()
}
```

- [ ] When `defer` encloses a function literal, analyze the deferred body
- [ ] If body references tainted variable from enclosing scope, emit finding
- [ ] Wire deferred closure into call graph as callee of enclosing function

---

## Phase 6.5: Goroutine Closures — IP-010

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

- [ ] When `go func() { ... }()` encountered, analyze closure body
- [ ] If body references tainted variables from enclosing scope, propagate taint into goroutine
- [ ] Wire goroutine closure into call graph with `goroutine: true` flag
- [x] Fixture files created (IP-010-vulnerable.txt and IP-010-safe.txt exist)
- [ ] Enable IP-010 in `tests/go_taint_integration.rs`

---

## Phase 6.6: Additional Deferred Fixtures

### Closure capture — IP-008

```go
func caller() {
    x := r.URL.Query().Get("input")
    fn := func() {
        os.Open(x)  // should fire CWE-22 (captured)
    }
    fn()
}
```

- [ ] Implement closure variable capture tracking
- [x] Fixture files created (IP-008-vulnerable.txt and IP-008-safe.txt exist)
- [ ] Enable IP-008 in test runner

### Multiple returns — IP-009

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
- [ ] Handle multi-return taint propagation through `TaintSummary.return_sources`
- [ ] Enable IP-009 in test runner

---

## Phase 6.7: Interface Dispatch

- [ ] **ponytail:** Interface dispatch not supported in initial implementation
- [ ] When method called on interface type, mark call as opaque (no callee resolution)
- [ ] Taint flows through arguments but not return value
- [ ] Document limitation in `docs/taint.md`

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
