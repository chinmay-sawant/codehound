//! BP-3, BP-13, BP-15 — panic, context, and sync.Once detectors.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-3: `panic(...)` called outside `main()` or test files.
pub(crate) fn detect_bp_3_panic_outside_main(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("panic(") {
        return;
    }
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let is_test_file = file.ends_with("_test.go");

    fn walk(
        node: Node,
        src: &[u8],
        file: &str,
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        is_test_file: bool,
        in_main: bool,
    ) {
        let mut in_main = in_main;
        if node.kind() == "function_declaration"
            && let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
        {
            in_main = name == "main";
        }
        if node.kind() == "call_expression"
            && let Some(func) = node.child_by_field_name("function")
            && func.utf8_text(src).ok() == Some("panic")
            && !in_main
            && !is_test_file
        {
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
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out, is_test_file, in_main);
        }
    }

    walk(root, src, file, unit, out, is_test_file, false);
}

/// BP-13: context.Background used outside main/test code.
pub(crate) fn detect_bp_13_background_context_in_library(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("context.Background") && !unit.source.contains("context.Background") {
        return;
    }
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
    if !unit.source.contains(".Do(") || !unit.source.contains("Once") {
        return;
    }
    let src = unit.source.as_bytes();
    let function_facts = collect_function_facts(unit.tree.root_node(), src);

    fn walk(
        node: Node,
        src: &[u8],
        unit: &ParsedUnit,
        function_facts: &HashMap<String, CallFacts>,
        out: &mut Vec<Finding>,
    ) {
        if node.kind() == "call_expression"
            && let Some(once_name) = called_once_receiver(node, src)
            && let Some(closure) = find_func_literal(node)
        {
            let closure_facts = collect_call_facts(closure, src);
            let recursive = closure_facts
                .once_receivers
                .iter()
                .any(|receiver| receiver == once_name)
                || closure_facts.local_calls.iter().any(|callee| {
                    closure_reaches_same_once(
                        callee,
                        once_name,
                        function_facts,
                        &mut HashSet::new(),
                    )
                });

            if recursive {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_15_META,
                    node.start_byte(),
                    "sync.Once.Do closure recursively calls the same Once",
                );
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, function_facts, out);
        }
    }

    walk(unit.tree.root_node(), src, unit, &function_facts, out);
}

#[derive(Default)]
struct CallFacts {
    local_calls: Vec<String>,
    once_receivers: Vec<String>,
}

fn collect_function_facts(root: Node, src: &[u8]) -> HashMap<String, CallFacts> {
    let mut facts = HashMap::new();

    fn walk(node: Node, src: &[u8], facts: &mut HashMap<String, CallFacts>) {
        if matches!(node.kind(), "function_declaration" | "method_declaration")
            && let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| child.utf8_text(src).ok())
        {
            facts.insert(name.to_string(), collect_call_facts(node, src));
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, facts);
        }
    }

    walk(root, src, &mut facts);
    facts
}

fn collect_call_facts(node: Node, src: &[u8]) -> CallFacts {
    let mut facts = CallFacts::default();

    fn walk(node: Node, src: &[u8], facts: &mut CallFacts) {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && let Ok(text) = function.utf8_text(src)
        {
            if let Some(receiver) = text.strip_suffix(".Do") {
                facts.once_receivers.push(receiver.to_string());
            } else if is_local_function_name(text) {
                facts.local_calls.push(text.to_string());
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, facts);
        }
    }

    walk(node, src, &mut facts);
    facts
}

fn called_once_receiver<'a>(node: Node, src: &'a [u8]) -> Option<&'a str> {
    let function = node.child_by_field_name("function")?;
    let text = function.utf8_text(src).ok()?;
    let receiver = text.strip_suffix(".Do")?;
    is_local_function_name(receiver).then_some(receiver)
}

fn find_func_literal(node: Node) -> Option<Node> {
    if node.kind() == "func_literal" {
        return Some(node);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = find_func_literal(child) {
            return Some(found);
        }
    }
    None
}

fn closure_reaches_same_once(
    function_name: &str,
    once_name: &str,
    function_facts: &HashMap<String, CallFacts>,
    visiting: &mut HashSet<String>,
) -> bool {
    if !visiting.insert(function_name.to_string()) {
        return false;
    }
    let Some(facts) = function_facts.get(function_name) else {
        return false;
    };

    facts
        .once_receivers
        .iter()
        .any(|receiver| receiver == once_name)
        || facts
            .local_calls
            .iter()
            .any(|callee| closure_reaches_same_once(callee, once_name, function_facts, visiting))
}

fn is_local_function_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}
