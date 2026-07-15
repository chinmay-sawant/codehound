# v0.0.3 — Performance Analysis & Optimization Plan

> **Parent:** `plans/v0.0.3/`
> **Status:** Approved; ready for implementation
> **Estimated effort:** 1-2 days

---

## Overview

An analysis of a clean run of `codehound` shows that it takes approximately **5.4 seconds** to scan 78 files (28,120 lines). This report details where the time is spent and how to squeeze maximum performance out of the scanner without altering any existing detection logic.

---

## Executive Summary

- **Primary Bottleneck**: The `GoBadPracticeScan` detector (reported under `BP-1` in timings) consumes **89.5%** of the total execution time (**98.9s** cumulative thread-time out of **110.4s**).
- **Underlying Cause**:
  1. **Redundant Traversals**: Unlike the `CWE` and `PERF` suites which compile a shared facts structure, the `Bad Practices` suite runs 80+ rules sequentially, each performing separate recursive AST traversals.
  2. **Cursor Overhead**: Many AST walks instantiate a new tree-sitter `TreeCursor` at every single node/recursion level, incurring massive memory allocation and call-stack overhead.
  3. **No Short-Circuiting**: Most bad practice rules lack fast-path substring checks, walking the entire AST of every file even when the targeted pattern/keyword (e.g. `defer`, `time.After`) is completely absent.
- **Preflight Serial Bottleneck**: Reading and hashing all files to check cache hits is done sequentially on the main thread.

---

## Phase 1: Fast-Path Substring Short-Circuiting (Rule Level)

For rules that walk the AST, checking if a specific keyword or character exists in the file's raw source text is extremely fast using Rust's SIMD-accelerated `contains` method. Adding short-circuit checks at the entry points of rules will bypass AST walks for files that cannot match.

- [ ] Add fast-path check to `detect_bp_1_discarded_error` in `error_handling.rs`
- [ ] Add fast-path check to `detect_bp_10_time_after_in_loop` in `loops.rs`
- [ ] Add fast-path check to `detect_bp_11_defer_in_loop` in `loops.rs`

### Code Reference

```rust
// src/lang/go/detectors/bad_practices/rules/error_handling.rs

pub(crate) fn detect_bp_1_discarded_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    // Fast-path: A discarded error assignment must contain both '_' and '=' (or ':=')
    if !unit.source.contains('_') || !unit.source.contains('=') {
        return;
    }

    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    ...
}
```

```rust
// src/lang/go/detectors/bad_practices/rules/loops.rs

pub(crate) fn detect_bp_10_time_after_in_loop(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains("time.After") {
        return;
    }
    ...
}

pub(crate) fn detect_bp_11_defer_in_loop(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains("defer") {
        return;
    }
    ...
}
```

---

## Phase 2: Single-Cursor Traversals

Creating a `TreeCursor` at every recursion level is highly inefficient. We can leverage the existing `walk_nodes` helper in `src/ast/walk.rs`, which instantiates only a single cursor for the entire tree traversal.

- [ ] Replace custom recursive `walk` function in `detect_bp_1_discarded_error` with `crate::ast::walk_nodes`

### Code Reference

```rust
// src/lang/go/detectors/bad_practices/rules/error_handling.rs

pub(crate) fn detect_bp_1_discarded_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains('_') || !unit.source.contains('=') {
        return;
    }
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    crate::ast::walk_nodes(
        root,
        &["assignment_statement", "short_var_declaration"],
        &mut |node| {
            if let Ok(text) = node.utf8_text(src) {
                if let Some((lhs, rhs)) = split_assign(text) {
                    if rhs.contains('(')
                        && !is_non_error_builtin_rhs(rhs)
                        && lhs_discards_possible_error(lhs)
                    {
                        let (line, col) = unit.line_col(node.start_byte());
                        emit::push_finding(
                            &crate::lang::go::detectors::bad_practices::BP_1_META,
                            file,
                            line,
                            col,
                            "discarded error return; handle or explicitly ignore with a comment",
                            out,
                        );
                    }
                }
            }
        },
    );
}
```

---

## Phase 3: Optimize Package-Level Scope Scans

Helper functions like `collect_unexported_helpers` search for function and method declarations. In Go, these can only occur at the package level (directly under the root node). Recursively walking the entire AST of every file to find them is completely redundant.

- [ ] Optimize `collect_unexported_helpers` in `code_organization.rs` to only iterate over immediate root children rather than performing a deep AST walk

### Code Reference

```rust
// src/lang/go/detectors/bad_practices/rules/code_organization.rs

fn collect_unexported_helpers(root: Node, src: &[u8]) -> Vec<(String, usize)> {
    let mut helpers = Vec::new();

    // Named helper functions and methods can only be declared at package scope.
    // Only iterate direct children of the root node to avoid deep AST walking.
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if matches!(child.kind(), "function_declaration" | "method_declaration")
            && let Some(name) = declaration_name(child, src)
            && name != "init"
            && !is_exported(name)
        {
            helpers.push((name.to_string(), child.start_byte()));
        }
    }

    helpers
}
```

---

## Phase 4: Parallelize Cache Preflight Checks

During startup, `preflight_cache_hits` reads and hashes every file sequentially on the main thread. By leveraging `rayon::prelude::*`, this phase can run concurrently, allowing file reading and SHA-256 calculation to occur across all CPU cores.

- [ ] Parallelize Phase 1 of `preflight_cache_hits` in `parallel.rs` using Rayon to compute file hashes and perform lookups concurrently

---

## Dependencies

- No external crates/modules dependencies are introduced.
- Uses existing `walk_nodes` helper in `src/ast/walk.rs` and standard `rayon` features already present in `Cargo.toml`.
