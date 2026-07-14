//! Batch A follow-up candidates with narrow source-only proof.
//!
//! Registration, metadata, dispatch, and fixture-manifest integration are
//! intentionally left to the coordinating agent.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-68: `errors.Join` returns a new error. A bare call or an assignment to
/// `_` discards that value and therefore cannot combine the supplied errors.
pub(crate) fn detect_bp_68_discarded_errors_join(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_bp_68(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_68(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression"
        && call_name(node, source) == Some("errors.Join")
        && is_discarded_call(node, source)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_68_META,
            node.start_byte(),
            "errors.Join result is discarded; return or assign the combined error",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_68(child, source, unit, out);
    }
}

fn is_discarded_call(node: Node, source: &[u8]) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };

    if parent.kind() == "expression_statement" {
        return true;
    }

    if parent.kind() != "assignment_statement" {
        return false;
    }

    let Ok(statement) = parent.utf8_text(source) else {
        return false;
    };
    let Some((left, _)) = statement
        .split_once(":=")
        .or_else(|| statement.split_once('='))
    else {
        return false;
    };
    left.trim() == "_"
}

/// BP-85: a single-value assertion on a value obtained from `Context.Value`
/// can panic when request-scoped data is absent or has the wrong type. The
/// detector is intentionally limited to net/http handlers and this explicit
/// boundary shape; arbitrary assertions elsewhere are not proof of a defect.
pub(crate) fn detect_bp_85_unchecked_handler_context_assertion(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }

    walk_functions_bp_85(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_functions_bp_85(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if matches!(node.kind(), "function_declaration" | "method_declaration")
        && is_net_http_handler(node, source)
        && let Some(body) = node.child_by_field_name("body")
    {
        walk_assertions_bp_85(body, source, unit, out);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions_bp_85(child, source, unit, out);
    }
}

fn walk_assertions_bp_85(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "type_assertion_expression"
        && is_context_value_assertion(node, source)
        && !is_checked_assertion(node, source)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_85_META,
            node.start_byte(),
            "request context value is asserted without an ok check; handle a missing or wrong-typed value",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_assertions_bp_85(child, source, unit, out);
    }
}

fn is_net_http_handler(node: Node, source: &[u8]) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let header = &source[node.start_byte()..body.start_byte()];
    let header = std::str::from_utf8(header).unwrap_or_default();
    header.contains("http.ResponseWriter") && header.contains("*http.Request")
}

fn is_context_value_assertion(node: Node, source: &[u8]) -> bool {
    node.utf8_text(source)
        .is_ok_and(|text| text.contains(".Value("))
}

fn is_checked_assertion(node: Node, source: &[u8]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "assignment_statement" | "short_var_declaration"
        ) {
            let Ok(statement) = parent.utf8_text(source) else {
                return false;
            };
            let Some((left, _)) = statement
                .split_once(":=")
                .or_else(|| statement.split_once('='))
            else {
                return false;
            };
            return left.split(',').map(str::trim).any(|name| name == "ok");
        }
        if matches!(
            parent.kind(),
            "expression_statement" | "return_statement" | "argument_list"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}
