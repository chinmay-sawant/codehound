//! BP-84: integer division truncation used to calculate a percentage.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-84 flags only the narrow percentage-shaped expression
/// `(<simple operand> / <simple operand>) * 100` when the result is visibly
/// percentage-named. Go integer division truncates before the multiplication,
/// so values such as `1 / 3 * 100` become `0` rather than `33`.
///
/// This is intentionally syntax-only: without go/types, arbitrary identifiers
/// cannot be proven to have integer types. Requiring simple operands and a
/// percentage-shaped destination/function keeps the low-severity heuristic
/// away from general integer ratios and unrelated multiplication.
pub(crate) fn detect_bp_84_integer_percentage_truncation(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }

    walk(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "binary_expression"
        && operator(node, source) == Some("*")
        && node
            .child_by_field_name("right")
            .is_some_and(|right| right.utf8_text(source).ok() == Some("100"))
        && is_percentage_division(node, source)
        && has_percentage_context(node, source)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_84_META,
            node.start_byte(),
            "integer division truncates before percentage scaling; convert to a floating-point value before dividing",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, source, unit, out);
    }
}

fn is_percentage_division(node: Node, source: &[u8]) -> bool {
    let Some(division) = node.child_by_field_name("left") else {
        return false;
    };
    if division.kind() != "binary_expression" || operator(division, source) != Some("/") {
        return false;
    }

    let Some(numerator) = division.child_by_field_name("left") else {
        return false;
    };
    let Some(denominator) = division.child_by_field_name("right") else {
        return false;
    };

    is_simple_integer_operand(numerator, source) && is_simple_integer_operand(denominator, source)
}

fn is_simple_integer_operand(node: Node, source: &[u8]) -> bool {
    if !matches!(node.kind(), "identifier" | "int_literal") {
        return false;
    }

    let Ok(text) = node.utf8_text(source) else {
        return false;
    };

    node.kind() == "identifier" || is_integer_literal(text)
}

fn is_integer_literal(text: &str) -> bool {
    let text = text.replace('_', "");
    if text.is_empty() {
        return false;
    }

    if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_hexdigit());
    }
    if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        return !rest.is_empty() && rest.chars().all(|ch| matches!(ch, '0' | '1'));
    }
    if let Some(rest) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        return !rest.is_empty() && rest.chars().all(|ch| ('0'..='7').contains(&ch));
    }

    text.chars().all(|ch| ch.is_ascii_digit())
}

fn operator<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("operator")?.utf8_text(source).ok()
}

fn has_percentage_context(node: Node, source: &[u8]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "assignment_statement" | "short_var_declaration" | "return_statement"
        ) && let Ok(text) = parent.utf8_text(source)
            && percentage_lhs(text)
        {
            return true;
        }

        if matches!(parent.kind(), "function_declaration" | "method_declaration") {
            return parent
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(source).ok())
                .is_some_and(is_percentage_name);
        }
        current = parent.parent();
    }
    false
}

fn percentage_lhs(statement: &str) -> bool {
    let lhs = statement
        .split_once(":=")
        .or_else(|| statement.split_once('='))
        .map_or(statement, |(lhs, _)| lhs);
    lhs.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(is_percentage_name)
}

fn is_percentage_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("percent") || name.contains("percentage") || name.contains("pct")
}
