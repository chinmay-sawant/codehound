//! Phase 4 core-language candidates with same-function error-flow proof.
//!
//! Shared registration, metadata, dispatch, and fixture-manifest integration
//! are intentionally left to the coordinating agent.

use std::collections::HashSet;

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-66: compare a wrapped sentinel error with `==` or `!=`.
///
/// The detector requires local evidence that the same sentinel is wrapped by
/// `fmt.Errorf("...%w...", sentinel)` in the function. That keeps ordinary
/// exact comparisons out of the result while catching the case where wrapping
/// makes an exact comparison unreliable. Comparisons with `nil` and unrelated
/// package values are left alone.
pub(crate) fn detect_bp_66_wrapped_error_compared_directly(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }

    walk_functions(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_functions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if matches!(node.kind(), "function_declaration" | "method_declaration")
        && let Some(body) = node.child_by_field_name("body")
    {
        inspect_function(body, source, unit, out);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out);
    }
}

fn inspect_function(body: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let wrapped_sentinels = collect_wrapped_sentinels(body, source);
    if wrapped_sentinels.is_empty() {
        return;
    }

    walk_scope(body, body, source, &mut |node| {
        if node.kind() != "binary_expression" || operator(node, source) == Some("=") {
            return;
        }
        if !matches!(operator(node, source), Some("==") | Some("!=")) {
            return;
        }

        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        let Ok(left_text) = left.utf8_text(source) else {
            return;
        };
        let Ok(right_text) = right.utf8_text(source) else {
            return;
        };

        let left_text = normalize_expression(left_text);
        let right_text = normalize_expression(right_text);
        let directly_compared = if is_error_name(left_text) {
            right_text
        } else if is_error_name(right_text) {
            left_text
        } else {
            return;
        };

        if wrapped_sentinels.contains(directly_compared) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_66_META,
                node.start_byte(),
                "wrapped sentinel error is compared directly; use errors.Is instead of == or !=",
            );
        }
    });
}

fn collect_wrapped_sentinels(body: Node, source: &[u8]) -> HashSet<String> {
    let mut sentinels = HashSet::new();
    walk_scope(body, body, source, &mut |node| {
        if node.kind() != "call_expression" || call_name(node, source) != Some("fmt.Errorf") {
            return;
        }

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let args: Vec<Node> = arguments.named_children(&mut cursor).collect();
        let Some(format) = args.first().and_then(|arg| arg.utf8_text(source).ok()) else {
            return;
        };
        if !format.contains("%w") {
            return;
        }

        for argument in args.into_iter().skip(1) {
            let Ok(text) = argument.utf8_text(source) else {
                continue;
            };
            let text = normalize_expression(text);
            if is_sentinel_expression(text) {
                sentinels.insert(text.to_owned());
            }
        }
    });
    sentinels
}

fn walk_scope(node: Node, scope: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if node.id() != scope.id() && is_function(node) {
        return;
    }

    visit(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_scope(child, scope, source, visit);
    }
    let _ = source;
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn operator<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("operator")?.utf8_text(source).ok()
}

fn normalize_expression(text: &str) -> &str {
    let mut text = text.trim();
    while let Some(inner) = text
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    {
        text = inner.trim();
    }
    text
}

fn is_error_name(text: &str) -> bool {
    let text = text.trim();
    text == "err" || text == "error" || text.ends_with("Err") || text.ends_with("Error")
}

fn is_sentinel_expression(text: &str) -> bool {
    let name = text.rsplit('.').next().unwrap_or(text).trim();
    name.starts_with("Err")
        && name.len() > 3
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}
