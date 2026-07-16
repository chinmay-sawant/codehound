//! Batch C — narrowly gated HTTP framework correctness rules.
//!
//! This module is intentionally unregistered until the coordinator completes
//! the shared metadata, dispatch, and fixture-manifest integration. Every
//! detector requires both an explicit framework import and a framework-shaped
//! handler parameter; generic method-name matches are rejected.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-109: a Gin handler writes an error response but continues without an
/// abort or return, allowing later handler code to write a second response.
pub(crate) fn detect_bp_109_gin_error_response_without_abort(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/gin-gonic/gin") {
        return;
    }
    walk_functions(root, source, unit, out, inspect_gin_function);
}

fn inspect_gin_function(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some(contexts) = parameter_names(node, source, "*gin.Context") else {
        return;
    };
    if contexts.is_empty() {
        return;
    }

    collect_calls(node, &mut |call| {
        let Some((receiver, method)) = method_call(call, source) else {
            return;
        };
        if !contexts.contains(&receiver) || method != "JSON" {
            return;
        }
        if !call_has_error_status(call, source) || gin_call_is_terminated(call, source, &contexts) {
            return;
        }
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_109_META,
            call.start_byte(),
            "Gin error response is not followed by Abort or return; stop the handler after writing the error",
        );
    });
}

/// BP-116: an Echo handler writes an error response and then returns the raw
/// error, allowing Echo's error middleware to attempt a second response.
pub(crate) fn detect_bp_116_echo_response_error_double_handling(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/labstack/echo") {
        return;
    }
    walk_functions(root, source, unit, out, inspect_echo_function);
}

fn inspect_echo_function(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some(contexts) = parameter_names(node, source, "echo.Context") else {
        return;
    };
    if contexts.is_empty() {
        return;
    }

    collect_calls(node, &mut |call| {
        let Some((receiver, method)) = method_call(call, source) else {
            return;
        };
        if !contexts.contains(&receiver) || method != "JSON" {
            return;
        }
        if !call_has_error_status(call, source) || !followed_by_raw_error_return(call, source) {
            return;
        }
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_116_META,
            call.start_byte(),
            "Echo writes an error response and returns the raw error; choose one response-handling path",
        );
    });
}

fn walk_functions(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    inspect: fn(Node, &[u8], &ParsedUnit, &mut Vec<Finding>),
) {
    if is_function_like(node.kind()) {
        inspect(node, source, unit, out);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out, inspect);
    }
}

fn collect_calls<F>(node: Node, inspect: &mut F)
where
    F: FnMut(Node),
{
    if node.kind() == "call_expression" {
        inspect(node);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_function_like(child.kind()) {
            continue;
        }
        collect_calls(child, inspect);
    }
}

fn method_call<'a>(call: Node<'a>, source: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let function = call.child_by_field_name("function")?;
    let text = function.utf8_text(source).ok()?.trim();
    text.rsplit_once('.')
}

fn parameter_names<'a>(
    function: Node<'a>,
    source: &'a [u8],
    wanted_type: &str,
) -> Option<Vec<&'a str>> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut names = Vec::new();
    let mut cursor = parameters.walk();

    for parameter in parameters.named_children(&mut cursor) {
        let type_node = parameter.child_by_field_name("type")?;
        let type_text = type_node.utf8_text(source).ok()?.trim();
        if type_text != wanted_type {
            continue;
        }

        let declaration = parameter.utf8_text(source).ok()?.trim();
        let prefix = declaration.strip_suffix(type_text)?.trim();
        names.extend(
            prefix
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty() && *name != "_")
                .filter(|name| name.chars().all(is_identifier_char)),
        );
    }

    Some(names)
}

fn call_has_error_status(call: Node, source: &[u8]) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(status) = arguments.named_children(&mut cursor).next() else {
        return false;
    };
    let Ok(status) = status.utf8_text(source) else {
        return false;
    };
    let status = status.trim();
    status
        .parse::<u16>()
        .is_ok_and(|code| (400..=599).contains(&code))
        || matches!(
            status.rsplit('.').next().unwrap_or(status),
            "StatusBadRequest"
                | "StatusUnauthorized"
                | "StatusPaymentRequired"
                | "StatusForbidden"
                | "StatusNotFound"
                | "StatusMethodNotAllowed"
                | "StatusConflict"
                | "StatusUnprocessableEntity"
                | "StatusTooManyRequests"
                | "StatusInternalServerError"
                | "StatusNotImplemented"
                | "StatusBadGateway"
                | "StatusServiceUnavailable"
                | "StatusGatewayTimeout"
        )
}

fn gin_call_is_terminated(call: Node, source: &[u8], contexts: &[&str]) -> bool {
    let Some((block, statement)) = containing_block_statement(call) else {
        return false;
    };
    let mut after_statement = false;
    let mut cursor = block.walk();
    for sibling in block.named_children(&mut cursor) {
        if !after_statement {
            if sibling.id() == statement.id() {
                after_statement = true;
            }
            continue;
        }

        if sibling.kind() == "return_statement" {
            return true;
        }
        if is_abort_statement(sibling, source, contexts) {
            return true;
        }
    }
    false
}

fn is_abort_statement(statement: Node, source: &[u8], contexts: &[&str]) -> bool {
    if statement.kind() != "expression_statement" {
        return false;
    }
    let mut cursor = statement.walk();
    let Some(call) = statement.named_children(&mut cursor).next() else {
        return false;
    };
    if call.kind() != "call_expression" {
        return false;
    }
    method_call(call, source).is_some_and(|(receiver, method)| {
        contexts.contains(&receiver) && matches!(method, "Abort" | "AbortWithStatusJSON")
    })
}

fn followed_by_raw_error_return(call: Node, source: &[u8]) -> bool {
    let Some((block, statement)) = containing_block_statement(call) else {
        return false;
    };
    let mut after_statement = false;
    let mut cursor = block.walk();
    for sibling in block.named_children(&mut cursor) {
        if !after_statement {
            if sibling.id() == statement.id() {
                after_statement = true;
            }
            continue;
        }
        if sibling.kind() != "return_statement" {
            continue;
        }
        let Ok(text) = sibling.utf8_text(source) else {
            continue;
        };
        let returned = text.trim().strip_prefix("return").unwrap_or("").trim();
        if returned.chars().all(is_identifier_char)
            && (returned == "err" || returned.ends_with("Err"))
        {
            return true;
        }
    }
    false
}

fn containing_block_statement(node: Node) -> Option<(Node, Node)> {
    let mut current = node;
    loop {
        let parent = current.parent()?;
        if parent.kind() == "statement_list" {
            return Some((parent, current));
        }
        if parent.kind() == "block" {
            return Some((parent, current));
        }
        if is_function_like(parent.kind()) {
            return None;
        }
        current = parent;
    }
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

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}
