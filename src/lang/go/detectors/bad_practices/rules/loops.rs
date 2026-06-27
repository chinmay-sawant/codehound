//! BP-10, BP-11 — loop-related bad practices.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-10: time.After inside a loop.
pub(crate) fn detect_bp_10_time_after_in_loop(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn is_loop(node: Node) -> bool {
        matches!(node.kind(), "for_statement" | "range_statement")
    }

    fn walk(node: Node, src: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>, inside_loop: bool) {
        let inside_loop = inside_loop || is_loop(node);
        if inside_loop && node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.utf8_text(src).ok() == Some("time.After") {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_10_META,
                        node.start_byte(),
                        "time.After inside a loop allocates a new timer per iteration",
                    );
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, inside_loop);
        }
    }

    walk(root, src, unit, out, false);
}

/// BP-11: `defer` inside a `for`/`range` loop body.
pub(crate) fn detect_bp_11_defer_in_loop(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let file = unit.display_path.as_str();
    let root = unit.tree.root_node();

    fn is_loop(node: Node) -> bool {
        matches!(
            node.kind(),
            "for_statement" | "range_statement" | "for_clause" | "range_clause"
        )
    }

    fn walk(node: Node, file: &str, unit: &ParsedUnit, out: &mut Vec<Finding>, inside_loop: bool) {
        let inside_loop = inside_loop || is_loop(node);
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
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, file, unit, out, inside_loop);
        }
    }

    walk(root, file, unit, out, false);
}
