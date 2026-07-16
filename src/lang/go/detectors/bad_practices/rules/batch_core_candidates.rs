//! Batch A candidates: narrow core-language and context correctness checks.
//!
//! These detectors are intentionally unregistered until their metadata,
//! dispatch entries, and fixture-manifest rows are promoted by the integrator.
//! The source-only gates avoid claiming type or intent information that the
//! current tree-sitter facts cannot prove.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-67: `errors.As` requires its target argument to be an addressable
/// pointer. Passing the target value directly causes the standard library to
/// panic at runtime.
pub(crate) fn detect_bp_67_errors_as_target_not_pointer(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_bp_67(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_67(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression"
        && call_name(node, source) == Some("errors.As")
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        let mut cursor = arguments.walk();
        let mut named = arguments.named_children(&mut cursor);
        let _error_value = named.next();
        if let Some(target) = named.next()
            && target
                .utf8_text(source)
                .is_ok_and(|text| !is_address_expression(text))
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_67_META,
                target.start_byte(),
                "errors.As target must be passed by address; pass &target to avoid a runtime panic",
            );
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_67(child, source, unit, out);
    }
}

/// BP-75: copying into a known zero-length slice cannot copy any element.
/// This batch accepts only a local zero-value destination and a non-empty
/// slice literal as the source, so identifiers with unknown runtime length are
/// left alone.
pub(crate) fn detect_bp_75_copy_into_zero_length_slice(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains("copy(") {
        return;
    }
    crate::ast::walk_nodes(
        unit.tree.root_node(),
        &["function_declaration", "method_declaration"],
        &mut |node| {
            inspect_function_bp_75(node, unit.source.as_bytes(), unit, out);
        },
    );
}

#[derive(Clone, Copy)]
struct ZeroSlice<'a> {
    name: &'a str,
    declaration: Node<'a>,
    scope_id: usize,
}

fn inspect_function_bp_75(
    function: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
) {
    let Some(body) = function.child_by_field_name("body") else {
        return;
    };

    let mut zero_slices = Vec::new();
    collect_zero_slices(body, body, source, &mut zero_slices);
    find_zero_length_copies(body, body, source, unit, &zero_slices, out);
}

fn collect_zero_slices<'a>(
    node: Node<'a>,
    body: Node<'a>,
    source: &'a [u8],
    out: &mut Vec<ZeroSlice<'a>>,
) {
    if node.id() != body.id() && is_function(node) {
        return;
    }

    if matches!(
        node.kind(),
        "var_declaration" | "short_var_declaration" | "assignment_statement"
    ) && let Some(name) = zero_slice_binding(node, source)
        && let Some(scope) = enclosing_scope(node, body)
    {
        out.push(ZeroSlice {
            name,
            declaration: node,
            scope_id: scope.id(),
        });
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_zero_slices(child, body, source, out);
    }
}

fn find_zero_length_copies(
    node: Node,
    body: Node,
    source: &[u8],
    unit: &ParsedUnit,
    zero_slices: &[ZeroSlice<'_>],
    out: &mut Vec<Finding>,
) {
    if node.id() != body.id() && is_function(node) {
        return;
    }

    if node.kind() == "call_expression"
        && call_name(node, source) == Some("copy")
        && let Some(arguments) = node.child_by_field_name("arguments")
    {
        let mut cursor = arguments.walk();
        let mut named = arguments.named_children(&mut cursor);
        let destination = named.next();
        let source_value = named.next();
        if let (Some(destination), Some(source_value)) = (destination, source_value)
            && let (Ok(destination_text), Ok(source_text)) = (
                destination.utf8_text(source),
                source_value.utf8_text(source),
            )
            && is_non_empty_slice_literal(source_text)
            && let Some(scope) = enclosing_scope(node, body)
            && let Some(zero_slice) = zero_slices.iter().find(|candidate| {
                candidate.name == destination_text.trim()
                    && candidate.scope_id == scope.id()
                    && candidate.declaration.end_byte() < node.start_byte()
            })
            && !has_reassignment_between(
                body,
                source,
                zero_slice.name,
                zero_slice.declaration.end_byte(),
                node.start_byte(),
            )
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_75_META,
                destination.start_byte(),
                "copy destination has length zero; allocate it with the source length before copying",
            );
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        find_zero_length_copies(child, body, source, unit, zero_slices, out);
    }
}

fn zero_slice_binding<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let text = node.utf8_text(source).ok()?.trim();

    if let Some(declaration) = text.strip_prefix("var ") {
        let mut parts = declaration.split_whitespace();
        let name = parts.next()?;
        let slice_type = parts.next()?;
        if parts.next().is_none() && slice_type.starts_with("[]") && is_identifier(name) {
            return Some(name);
        }
    }

    let (left, right) = text.split_once(":=").or_else(|| text.split_once('='))?;
    let name = left.trim();
    if !is_identifier(name) || !is_zero_length_make(right.trim()) {
        return None;
    }
    Some(name)
}

fn is_zero_length_make(text: &str) -> bool {
    let Some(arguments) = text.strip_prefix("make(") else {
        return false;
    };
    let Some((slice_type, length)) = arguments.split_once(',') else {
        return false;
    };
    slice_type.trim().starts_with("[]")
        && length
            .trim()
            .trim_end_matches(')')
            .split(',')
            .next()
            .is_some_and(|value| value.trim() == "0")
}

fn is_non_empty_slice_literal(text: &str) -> bool {
    let text = text.trim();
    let Some(open) = text.find('{') else {
        return false;
    };
    let Some(close) = text.rfind('}') else {
        return false;
    };
    text.starts_with("[]") && open < close && !text[open + 1..close].trim().is_empty()
}

fn is_address_expression(text: &str) -> bool {
    let mut text = text.trim();
    while let Some(inner) = text
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    {
        text = inner.trim();
    }
    text.starts_with('&')
}

fn has_reassignment_between(
    node: Node,
    source: &[u8],
    name: &str,
    start: usize,
    end: usize,
) -> bool {
    if matches!(
        node.kind(),
        "assignment_statement" | "short_var_declaration"
    ) && node.start_byte() >= start
        && node.end_byte() <= end
        && node
            .utf8_text(source)
            .is_ok_and(|text| assignment_targets_name(text, name))
    {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| has_reassignment_between(child, source, name, start, end))
}

fn assignment_targets_name(text: &str, name: &str) -> bool {
    let Some((left, _)) = text.split_once(":=").or_else(|| text.split_once('=')) else {
        return false;
    };
    left.split(',').any(|part| part.trim() == name)
}

/// BP-80: `context.TODO()` leaves a production context unresolved. This is
/// exact-call matching only; test files are excluded and `Background` is left
/// to the existing BP-13 detector.
pub(crate) fn detect_bp_80_context_todo_in_production(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_bp_80(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_80(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression" && call_name(node, source) == Some("context.TODO") {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_80_META,
            node.start_byte(),
            "context.TODO leaves a production context unresolved; propagate a real context instead",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_80(child, source, unit, out);
    }
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn enclosing_scope<'a>(mut node: Node<'a>, body: Node<'a>) -> Option<Node<'a>> {
    loop {
        if node.kind() == "block" || node.id() == body.id() {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}
