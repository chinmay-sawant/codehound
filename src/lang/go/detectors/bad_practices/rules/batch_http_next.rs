//! Batch B — narrowly gated HTTP failure-path correctness rules.
//!
//! The coordinator registers admitted rules after reviewing overlap, metadata,
//! dispatch, and fixture-manifest ownership. This module intentionally keeps
//! BP-102 narrow: generic `err != nil { return }` checks are not enough without
//! an explicit net/http handler shape.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-102: a net/http handler returns from an error path without writing an
/// error response or status. The detector requires an explicit ResponseWriter,
/// Request, and locally visible error binding to avoid flagging ordinary
/// helper functions or intentional no-content branches.
pub(crate) fn detect_bp_102_http_error_path_without_status(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "net/http") {
        return;
    }
    walk_functions(root, source, unit, out);
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
    // A standard net/http handler returns no result. Requiring that shape keeps
    // this rule away from framework handlers that intentionally return errors.
    if node.child_by_field_name("result").is_some() {
        return;
    }

    let Some((writers, has_request)) = handler_parameters(node, source) else {
        return;
    };
    if writers.is_empty() || !has_request {
        return;
    }

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    let findings_before = out.len();
    collect_if_statements(body, source, unit, out, &writers);
    if out.len() == findings_before {
        let Ok(body_text) = body.utf8_text(source) else {
            return;
        };
        if body_text.contains("!= nil")
            && body_text.contains("return")
            && !body_text.contains("http.Error")
            && !body_text.contains("WriteHeader")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_102_META,
                body.start_byte(),
                "HTTP error path returns without writing an error response or status",
            );
        }
    }
}

fn collect_if_statements(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    writers: &[&str],
) {
    if node.kind() == "if_statement" && matches_error_guard(node, source) {
        if let (Some(error_name), Some(function)) =
            (error_guard_name(node, source), enclosing_function(node))
        {
            let consequence = node.child_by_field_name("consequence");
            let has_bare_return = consequence
                .is_some_and(|consequence| has_direct_bare_return(consequence, source))
                || (consequence.is_none()
                    && node
                        .utf8_text(source)
                        .is_ok_and(|text| text.contains("return")));
            let has_response = consequence
                .is_some_and(|consequence| has_response_action(consequence, source, writers));
            if has_error_binding(function, source, error_name) && has_bare_return && !has_response {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_102_META,
                    node.start_byte(),
                    "HTTP error path returns without writing an error response or status",
                );
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_function_like(child.kind()) {
            continue;
        }
        collect_if_statements(child, source, unit, out, writers);
    }
}

fn matches_error_guard(node: Node, source: &[u8]) -> bool {
    let Some(condition) = node.child_by_field_name("condition") else {
        return node
            .utf8_text(source)
            .is_ok_and(|text| text.contains("!= nil"));
    };
    let Ok(condition_text) = condition.utf8_text(source) else {
        return false;
    };
    condition_text.contains("!= nil")
}

fn error_guard_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    if let Some(condition) = node.child_by_field_name("condition") {
        if let Some(left) = condition.child_by_field_name("left") {
            if let Ok(name) = left.utf8_text(source) {
                return Some(name);
            }
        }
        if let Some(name) = condition
            .utf8_text(source)
            .ok()?
            .split_once("!=")
            .map(|(name, _)| name.trim())
        {
            return Some(name);
        }
    }
    node.utf8_text(source)
        .ok()?
        .split_once("!=")
        .map(|(name, _)| name.trim_start_matches("if ").trim())
}

fn has_error_binding(function: Node, source: &[u8], error_name: &str) -> bool {
    let Ok(text) = function.utf8_text(source) else {
        return false;
    };
    let assignment = format!("{error_name} :=");
    let reassignment = format!("{error_name} =");
    text.contains(&assignment)
        || text.contains(&format!(", {error_name} :="))
        || text.contains(&reassignment)
}

fn has_direct_bare_return(node: Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        child.kind() == "return_statement"
            && child
                .utf8_text(source)
                .is_ok_and(|text| text.trim() == "return")
    })
}

fn has_response_action(node: Node, source: &[u8], writers: &[&str]) -> bool {
    if node.kind() == "call_expression" && is_response_call(node, source, writers) {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| has_response_action(child, source, writers))
}

fn is_response_call(node: Node, source: &[u8], writers: &[&str]) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let Ok(callee) = function.utf8_text(source) else {
        return false;
    };
    let callee = callee.trim();

    if matches!(
        callee,
        "http.Error" | "http.Redirect" | "http.NotFound" | "http.ServeFile"
    ) {
        return true;
    }

    let Some((receiver, method)) = callee.rsplit_once('.') else {
        return false;
    };
    writers.contains(&receiver) && matches!(method, "Write" | "WriteHeader")
}

fn handler_parameters<'a>(node: Node<'a>, source: &'a [u8]) -> Option<(Vec<&'a str>, bool)> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut writers = Vec::new();
    let mut has_request = false;
    let mut cursor = parameters.walk();

    for parameter in parameters.named_children(&mut cursor) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        let Ok(type_text) = type_node.utf8_text(source) else {
            continue;
        };
        let type_text = type_text.trim();
        let Ok(declaration) = parameter.utf8_text(source) else {
            continue;
        };
        let declaration = declaration.trim();

        if type_text == "http.ResponseWriter" {
            let names = declaration.strip_suffix(type_text)?.trim();
            writers.extend(
                names
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty() && *name != "_"),
            );
        }
        if type_text == "*http.Request" {
            has_request = true;
        }
    }

    if !writers.is_empty() && has_request {
        return Some((writers, has_request));
    }

    let body = node.child_by_field_name("body")?;
    let header = std::str::from_utf8(&source[node.start_byte()..body.start_byte()]).ok()?;
    let params = header.split_once('(')?.1.split_once(')')?.0;
    let mut fallback_writers = Vec::new();
    let mut fallback_request = false;
    for parameter in params.split(',').map(str::trim) {
        if parameter.contains("http.ResponseWriter") {
            if let Some(name) = parameter.split_whitespace().next() {
                fallback_writers.push(name);
            }
        }
        if parameter.contains("*http.Request") {
            fallback_request = true;
        }
    }
    Some((fallback_writers, fallback_request))
}

fn enclosing_function(mut node: Node) -> Option<Node> {
    while let Some(parent) = node.parent() {
        if is_function_like(parent.kind()) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    if root.kind() == "import_spec"
        && root
            .utf8_text(source)
            .is_ok_and(|text| text.contains(&format!("\"{path}")))
    {
        return true;
    }

    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|child| has_import(child, source, path))
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}
