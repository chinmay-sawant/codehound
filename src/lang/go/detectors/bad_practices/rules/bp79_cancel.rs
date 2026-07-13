//! BP-79 — locally bound context cancellation without visible local release.
//!
//! This is intentionally narrower than a general context-lifetime analysis. Go's
//! `lostcancel` vet analyzer already reports discarded cancel functions and
//! control-flow paths that return without using them. BP-79 only reports a
//! locally bound cancel function when this function contains no visible call or
//! defer for that identifier. A helper may own the function; this detector does
//! not attempt to decide that interprocedurally, so findings are review-only.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

const CONSTRUCTORS: [&str; 3] = [
    "context.WithCancel",
    "context.WithTimeout",
    "context.WithDeadline",
];

/// BP-79: a local context cancel function has no visible call or defer.
pub(crate) fn detect_bp_79_context_cancel_not_released(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    walk_functions(unit.tree.root_node(), source, unit, out);
}

fn walk_functions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if is_function(node) {
        inspect_function(node, source, unit, out);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out);
    }
}

fn inspect_function(function: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some(body) = function.child_by_field_name("body") else {
        return;
    };

    walk_body(body, body, source, unit, out);
}

fn walk_body(node: Node, body: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    // Nested functions have their own cancellation scope and are inspected by
    // walk_functions separately. Do not attribute their bindings to this body.
    if node.id() != body.id() && is_function(node) {
        return;
    }

    if matches!(node.kind(), "short_var_declaration" | "var_declaration")
        && let Some((cancel_name, constructor_byte)) = local_cancel_binding(node, source)
        && !has_visible_release(body, source, &cancel_name)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_79_META,
            constructor_byte,
            "locally bound context cancel function has no visible call or defer; verify its ownership and release path",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_body(child, body, source, unit, out);
    }
}

fn local_cancel_binding(node: Node, source: &[u8]) -> Option<(String, usize)> {
    let text = node.utf8_text(source).ok()?;
    let (lhs, rhs) = text.split_once(":=").or_else(|| text.split_once('='))?;
    let names: Vec<&str> = lhs
        .trim()
        .strip_prefix("var ")
        .unwrap_or(lhs.trim())
        .split(',')
        .map(str::trim)
        .collect();
    let cancel_name = names.get(1).copied()?.trim();
    if cancel_name.is_empty() || cancel_name == "_" {
        return None;
    }

    let constructor_offset = CONSTRUCTORS.iter().find_map(|constructor| {
        let offset = rhs.find(constructor)?;
        let after = rhs.get(offset + constructor.len()..)?;
        after.starts_with('(').then_some(offset)
    })?;

    let rhs_offset = text.len() - rhs.len();
    Some((
        cancel_name.to_owned(),
        node.start_byte() + rhs_offset + constructor_offset,
    ))
}

fn has_visible_release(body: Node, source: &[u8], cancel_name: &str) -> bool {
    fn walk(node: Node, source: &[u8], cancel_name: &str, body: Node) -> bool {
        if node.id() != body.id() && is_function(node) {
            return false;
        }

        if node.kind() == "defer_statement"
            && node
                .utf8_text(source)
                .is_ok_and(|text| contains_identifier_call(text, cancel_name))
        {
            return true;
        }

        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .and_then(|callee| callee.utf8_text(source).ok())
                .is_some_and(|callee| callee.trim() == cancel_name)
        {
            return true;
        }

        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| walk(child, source, cancel_name, body))
    }

    walk(body, source, cancel_name, body)
}

fn contains_identifier_call(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.contains(&format!("{name}()"))
            || trimmed.contains(&format!("{name} ("))
            || trimmed.contains(&format!("{name}\t("))
    })
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}
