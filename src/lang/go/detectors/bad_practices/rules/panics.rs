//! BP-3, BP-13, BP-15 — panic, context, and sync.Once detectors.

use tree_sitter::Node;

use super::helpers::push_at;
use super::super::source_index::SourceIndex;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-3: `panic(...)` called outside `main()` or test files.
pub(crate) fn detect_bp_3_panic_outside_main(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
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

/// BP-13: context.Background used outside main/test code.
pub(crate) fn detect_bp_13_background_context_in_library(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let file = unit.display_path.as_str();
    if file.ends_with("_test.go") {
        return;
    }
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut function_stack: Vec<String> = Vec::new();

    fn walk(
        node: Node,
        src: &[u8],
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        function_stack: &mut Vec<String>,
    ) {
        let pushed = if node.kind() == "function_declaration" {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
            {
                function_stack.push(name.to_string());
                true
            } else {
                false
            }
        } else {
            false
        };

        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.utf8_text(src).ok() == Some("context.Background")
                    && function_stack
                        .last()
                        .is_some_and(|name| name != "main" && name != "init")
                {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_13_META,
                        node.start_byte(),
                        "context.Background used in library code; accept and propagate a caller context",
                    );
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, function_stack);
        }
        if pushed {
            function_stack.pop();
        }
    }

    walk(root, src, unit, out, &mut function_stack);
}

/// BP-15: sync.Once.Do recursively calls the same Once.
pub(crate) fn detect_bp_15_recursive_once_do(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    let Some(do_pos) = source.find(".Do(func()") else {
        return;
    };
    let prefix = &source[..do_pos];
    let once_name = prefix
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    if once_name.is_empty() {
        return;
    }
    let body = &source[do_pos..];
    let recursive_call = format!("{once_name}.Do(");
    if body.contains(&recursive_call) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_15_META,
            do_pos,
            "sync.Once.Do closure recursively calls the same Once",
        );
    }
}
