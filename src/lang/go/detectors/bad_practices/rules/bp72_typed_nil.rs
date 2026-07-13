//! BP-72 — typed nil pointer returned through an interface.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-72: a typed nil pointer is returned from a function whose visible result
/// type is `error` or an anonymous interface. The interface then contains a
/// dynamic pointer type and is not itself nil.
///
/// The detector intentionally accepts only the direct, locally provable form:
/// `var p *T = nil` followed by `return p`, with no intervening assignment to
/// `p`. It does not infer named interfaces, aliases, or interprocedural flow.
pub(crate) fn detect_bp_72_typed_nil_interface_return(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    walk_functions(unit.tree.root_node(), source, unit, out);
}

fn walk_functions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if matches!(node.kind(), "function_declaration" | "method_declaration") {
        inspect_function(node, source, unit, out);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out);
    }
}

fn inspect_function(function: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some(result) = function.child_by_field_name("result") else {
        return;
    };
    let Some(result_text) = result.utf8_text(source).ok() else {
        return;
    };
    if !is_single_interface_or_error_result(result_text) {
        return;
    }

    let Some(body) = function.child_by_field_name("body") else {
        return;
    };
    let mut declarations = Vec::new();
    let mut returns = Vec::new();
    collect_candidates(
        body,
        function.start_byte(),
        source,
        &mut declarations,
        &mut returns,
    );

    for return_node in returns {
        let Some(name) = returned_identifier(return_node, source) else {
            continue;
        };
        let Some(declaration) = declarations.iter().find(|declaration| {
            declaration.name == name && declaration.node.end_byte() < return_node.start_byte()
        }) else {
            continue;
        };
        if has_assignment_between(
            body,
            function.start_byte(),
            source,
            name,
            declaration.node.end_byte(),
            return_node.start_byte(),
        ) {
            continue;
        }

        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_72_META,
            return_node.start_byte(),
            "typed nil pointer returned as an error/interface produces a non-nil interface",
        );
    }
}

#[derive(Clone, Copy)]
struct TypedNilDeclaration<'a> {
    name: &'a str,
    node: Node<'a>,
}

fn collect_candidates<'a>(
    node: Node<'a>,
    function_start: usize,
    source: &'a [u8],
    declarations: &mut Vec<TypedNilDeclaration<'a>>,
    returns: &mut Vec<Node<'a>>,
) {
    if node.kind() == "function_literal" && node.start_byte() != function_start {
        return;
    }
    if node.kind() == "var_declaration"
        && let Some((name, _pointer_type)) = typed_nil_declaration(node, source)
    {
        declarations.push(TypedNilDeclaration { name, node });
    }
    if node.kind() == "return_statement" {
        returns.push(node);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_candidates(child, function_start, source, declarations, returns);
    }
}

fn typed_nil_declaration<'a>(node: Node<'a>, source: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let text = node.utf8_text(source).ok()?.trim();
    let declaration = text.strip_prefix("var ")?;
    let (left, right) = declaration.split_once('=')?;
    if right.trim() != "nil" {
        return None;
    }
    let mut parts = left.split_whitespace();
    let name = parts.next()?;
    let pointer_type = parts.next()?;
    if parts.next().is_some() || !pointer_type.starts_with('*') || !is_identifier(name) {
        return None;
    }
    Some((name, pointer_type))
}

fn is_single_interface_or_error_result(text: &str) -> bool {
    let result = text
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    if result.contains(',') {
        return false;
    }
    let mut parts = result.split_whitespace();
    let first = parts.next().unwrap_or_default();
    if first == "error" || first == "interface" || first.starts_with("interface{") {
        return true;
    }
    if first.is_empty() {
        return false;
    }
    let second = parts.next().unwrap_or_default();
    second == "error" || second == "interface" || second.starts_with("interface{")
}

fn returned_identifier<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let text = node.utf8_text(source).ok()?.trim();
    let expression = text.strip_prefix("return")?.trim();
    is_identifier(expression).then_some(expression)
}

fn has_assignment_between(
    node: Node,
    function_start: usize,
    source: &[u8],
    name: &str,
    start: usize,
    end: usize,
) -> bool {
    if node.kind() == "function_literal" && node.start_byte() != function_start {
        return false;
    }
    if (node.kind() == "assignment_statement" || node.kind() == "short_var_declaration")
        && node.start_byte() >= start
        && node.end_byte() <= end
        && assignment_targets_name(node, source, name)
    {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| has_assignment_between(child, function_start, source, name, start, end))
}

fn assignment_targets_name(node: Node, source: &[u8], name: &str) -> bool {
    let Some(text) = node.utf8_text(source).ok() else {
        return false;
    };
    let Some((left, _right)) = text.split_once('=') else {
        return false;
    };
    left.split(',').any(|part| {
        let part = part.trim();
        part == name
            || part.strip_prefix(name).is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(is_assignment_operator)
            })
    })
}

fn is_assignment_operator(ch: char) -> bool {
    matches!(
        ch,
        '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '<' | '>' | ' ' | '\t'
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
