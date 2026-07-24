//! BP-101 — net/http handlers write a body before setting the status header.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-101: a net/http handler writes its response body before WriteHeader.
///
/// This is deliberately narrower than a generic method-order check. It requires
/// the function to have both an `http.ResponseWriter` and an `*http.Request`
/// parameter, plus a net/http import. Body writes are limited to that writer
/// (`Write`) or standard-library formatting/string helpers targeting it.
pub(crate) fn detect_bp_101_http_header_after_body(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    if !has_net_http_import(unit.tree.root_node(), source) {
        return;
    }
    walk_functions(unit.tree.root_node(), source, unit, out);
}

fn walk_functions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if is_function_like(node.kind()) {
        inspect_handler(node, source, unit, out);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out);
    }
}

fn inspect_handler(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some((writers, has_request)) = handler_parameters(node, source) else {
        return;
    };
    if writers.is_empty() || !has_request {
        return;
    }

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    inspect_blocks(body, source, unit, &writers, out);
}

fn inspect_blocks(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    writers: &[&str],
    out: &mut Vec<Finding>,
) {
    if node.kind() == "block" {
        inspect_direct_calls(node, source, unit, writers, out);
    }
    if is_function_like(node.kind()) {
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        inspect_blocks(child, source, unit, writers, out);
    }
}

fn inspect_direct_calls(
    block: Node,
    source: &[u8],
    unit: &ParsedUnit,
    writers: &[&str],
    out: &mut Vec<Finding>,
) {
    let mut calls = Vec::new();
    collect_direct_calls(block, source, writers, &mut calls);

    for (byte, kind) in calls {
        if kind != CallKind::WriteHeader {
            continue;
        }
        if calls_before_header(block, source, writers, byte) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_101_META,
                byte,
                "response body is written before WriteHeader; set the status before the first body write",
            );
        }
    }
}

fn calls_before_header(block: Node, source: &[u8], writers: &[&str], header_byte: usize) -> bool {
    let mut calls = Vec::new();
    collect_direct_calls(block, source, writers, &mut calls);
    calls
        .into_iter()
        .any(|(byte, kind)| kind == CallKind::BodyWrite && byte < header_byte)
}

fn collect_direct_calls(
    node: Node,
    source: &[u8],
    writers: &[&str],
    calls: &mut Vec<(usize, CallKind)>,
) {
    if node.kind() == "call_expression"
        && let Some(kind) = classify_call(node, source, writers)
    {
        calls.push((node.start_byte(), kind));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "block" || is_function_like(child.kind()) {
            continue;
        }
        collect_direct_calls(child, source, writers, calls);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallKind {
    BodyWrite,
    WriteHeader,
}

fn classify_call(node: Node, source: &[u8], writers: &[&str]) -> Option<CallKind> {
    let function = node.child_by_field_name("function")?;
    let callee = function.utf8_text(source).ok()?.trim();

    if let Some((receiver, method)) = callee.rsplit_once('.')
        && writers.contains(&receiver)
    {
        return match method {
            "Write" => Some(CallKind::BodyWrite),
            "WriteHeader" => Some(CallKind::WriteHeader),
            _ => None,
        };
    }

    let writes_through_helper = matches!(
        callee,
        "fmt.Fprint" | "fmt.Fprintf" | "fmt.Fprintln" | "io.WriteString"
    );
    if writes_through_helper && first_argument_is_writer(node, source, writers) {
        return Some(CallKind::BodyWrite);
    }
    None
}

fn first_argument_is_writer(node: Node, source: &[u8], writers: &[&str]) -> bool {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .next()
        .and_then(|argument| argument.utf8_text(source).ok())
        .is_some_and(|argument| writers.contains(&argument.trim()))
}

fn handler_parameters<'a>(node: Node<'a>, source: &'a [u8]) -> Option<(Vec<&'a str>, bool)> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut writers = Vec::new();
    let mut has_request = false;
    let mut cursor = parameters.walk();

    for parameter in parameters.named_children(&mut cursor) {
        let type_node = parameter.child_by_field_name("type")?;
        let type_text = type_node.utf8_text(source).ok()?.trim();
        let declaration = parameter.utf8_text(source).ok()?.trim();

        if type_text == "http.ResponseWriter" {
            let names = declaration.strip_suffix(type_text)?.trim();
            for name in names.split(',').map(str::trim) {
                if !name.is_empty() && name != "_" {
                    writers.push(name);
                }
            }
        }
        if type_text == "*http.Request" {
            has_request = true;
        }
    }

    Some((writers, has_request))
}

fn has_net_http_import(root: Node, source: &[u8]) -> bool {
    if root.kind() == "import_spec"
        && root
            .utf8_text(source)
            .is_ok_and(|text| text.contains("\"net/http\""))
    {
        return true;
    }

    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|child| has_net_http_import(child, source))
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}
