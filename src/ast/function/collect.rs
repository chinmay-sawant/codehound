//! `FunctionSpan` data type + the `collect_function_spans` walker
//! (and its private `walk` + `try_record_function_span` helpers).

use tree_sitter::Node;

/// Byte/line range of a function-like node plus its nesting depth.
///
/// `depth` is `0` for the outermost function containing a finding, `1` for a
/// function nested inside it, and so on. [`super::span::enclosing_function`]
/// picks the deepest (smallest) span by `depth`, which is what callers
/// want when they ask "what function is this line in?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    /// 1-indexed start line.
    pub start_line: usize,
    /// 1-indexed end line.
    pub end_line: usize,
    pub depth: usize,
}

/// Walk the tree once and collect every node whose kind is in `kinds`,
/// recording the nesting depth of each match.
pub fn collect_function_spans(node: Node<'_>, kinds: &[&str]) -> Vec<FunctionSpan> {
    if kinds.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    walk(node, kinds, 0, &mut out);
    out
}

fn walk(root: Node<'_>, kinds: &[&str], depth: usize, out: &mut Vec<FunctionSpan>) {
    let mut cursor = root.walk();
    let mut depth_stack: Vec<usize> = vec![depth];
    loop {
        let node = cursor.node();
        let current_depth = *depth_stack.last().unwrap_or(&0);
        let is_fn = kinds.contains(&node.kind());
        if is_fn {
            out.push(FunctionSpan {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                depth: current_depth,
            });
        }
        if cursor.goto_first_child() {
            depth_stack.push(if is_fn {
                current_depth + 1
            } else {
                current_depth
            });
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
            depth_stack.pop();
        }
    }
}

/// Push a function span from a single node (if its kind is function-like).
/// Returns `true` when the node was function-like and a span was recorded.
///
/// Line numbers are set to `0`; the caller is responsible for resolving
/// them later (e.g. via [`crate::ast::line_col_with_starts`]).
#[allow(dead_code)]
pub(crate) fn try_record_function_span(
    node: Node<'_>,
    kinds: &[&str],
    depth: usize,
    out: &mut Vec<FunctionSpan>,
) -> bool {
    if kinds.contains(&node.kind()) {
        out.push(FunctionSpan {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: 0,
            end_line: 0,
            depth,
        });
        return true;
    }
    false
}
