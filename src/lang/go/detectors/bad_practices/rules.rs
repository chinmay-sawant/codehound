//! MVP bad-practice detectors.

use tree_sitter::Node;

use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-1: `_ = f()` where `f` likely returns an `error`.
pub(crate) fn detect_bp_1_discarded_error(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn walk(node: Node, src: &[u8], file: &str, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if node.kind() == "assignment_statement" || node.kind() == "short_var_declaration" {
            if let Ok(text) = node.utf8_text(src) {
                // Look for `_` on the LHS and a call on the RHS.
                if text.contains('_') && text.contains('(') && text.contains(')') {
                    let lhs = text
                        .split_once(":=")
                        .map(|(l, _)| l)
                        .or_else(|| text.split_once('=').map(|(l, _)| l));
                    if let Some(lhs) = lhs {
                        if lhs.split(',').map(str::trim).any(|name| name == "_") {
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
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out);
        }
    }

    walk(root, src, file, unit, out);
}

/// BP-3: `panic(...)` called outside `main()` or test files.
pub(crate) fn detect_bp_3_panic_outside_main(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    let is_test_file = file.ends_with("_test.go");
    let mut in_main = false;

    fn walk(
        node: Node,
        src: &[u8],
        file: &str,
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        is_test_file: bool,
        in_main: &mut bool,
    ) {
        if node.kind() == "function_declaration" {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
            {
                *in_main = name == "main";
            }
        }
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(text) = func.utf8_text(src) {
                    if text == "panic" && !*in_main && !is_test_file {
                        let (line, col) = unit.line_col(node.start_byte());
                        emit::push_finding(
                            &crate::lang::go::detectors::bad_practices::BP_3_META,
                            file,
                            line,
                            col,
                            "panic outside main() or test files; prefer returning errors up the call stack",
                            out,
                        );
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out, is_test_file, in_main);
        }
    }

    walk(root, src, file, unit, out, is_test_file, &mut in_main);
}

/// BP-11: `defer` inside a `for`/`range` loop body.
pub(crate) fn detect_bp_11_defer_in_loop(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn is_loop(node: Node) -> bool {
        matches!(
            node.kind(),
            "for_statement" | "range_statement" | "for_clause" | "range_clause"
        )
    }

    fn walk(
        node: Node,
        src: &[u8],
        file: &str,
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        inside_loop: bool,
    ) {
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
            walk(child, src, file, unit, out, inside_loop);
        }
    }

    walk(root, src, file, unit, out, false);
}
