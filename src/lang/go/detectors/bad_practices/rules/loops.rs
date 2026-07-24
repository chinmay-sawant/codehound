//! BP-10, BP-11 — loop-related bad practices.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-10: time.After inside a loop.
pub(crate) fn detect_bp_10_time_after_in_loop(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("time.After") {
        return;
    }

    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    walk_with_loop_context(root, |node, inside_loop| {
        if inside_loop
            && node.kind() == "call_expression"
            && let Some(func) = node.child_by_field_name("function")
            && func.utf8_text(src).ok() == Some("time.After")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_10_META,
                node.start_byte(),
                "time.After inside a loop allocates a new timer per iteration",
            );
        }
    });
}

/// BP-11: `defer` inside a `for`/`range` loop body.
pub(crate) fn detect_bp_11_defer_in_loop(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("defer") {
        return;
    }

    let file = unit.display_path.as_str();
    let root = unit.tree.root_node();
    walk_with_loop_context(root, |node, inside_loop| {
        if inside_loop && node.kind() == "defer_statement" {
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &crate::lang::go::detectors::bad_practices::BP_11_META,
                file,
                line,
                col,
                "defer inside a loop defers cleanup until the surrounding function returns",
                out,
            );
        }
    });
}

fn is_loop(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "for_statement" | "range_statement" | "for_clause" | "range_clause"
    )
}

/// Single-cursor DFS that tracks loop nesting without allocating a cursor per node.
fn walk_with_loop_context(root: Node<'_>, mut visit: impl FnMut(Node<'_>, bool)) {
    let mut cursor = root.walk();
    // Stack of "this node is a loop" for ancestors including current.
    let mut is_loop_stack: Vec<bool> = Vec::new();
    let mut loop_depth = 0usize;

    loop {
        let node = cursor.node();
        let node_is_loop = is_loop(node);
        is_loop_stack.push(node_is_loop);
        if node_is_loop {
            loop_depth += 1;
        }
        visit(node, loop_depth > 0);

        if cursor.goto_first_child() {
            continue;
        }

        // Backtrack until we can move to a next sibling.
        loop {
            if let Some(was_loop) = is_loop_stack.pop()
                && was_loop
            {
                loop_depth = loop_depth.saturating_sub(1);
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}
