//! Narrow admissions from the remaining core-language BP candidates.
//!
//! This module intentionally contains only source facts that are strong enough
//! to survive promotion. Registration, metadata, dispatch, and fixture-manifest
//! changes belong to the coordinating integration step.

use std::collections::HashSet;

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-76: map iteration is unordered, so feeding values collected directly
/// from a map into strings.Join produces unstable output. The detector admits
/// only a local map, an append from the same range clause, and a later Join of
/// that exact slice without an intervening sort call.
pub(crate) fn detect_bp_76_map_range_used_for_ordered_output(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_functions(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_functions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if is_function(node) {
        inspect_bp_76(node, source, unit, out);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out);
    }
}

fn inspect_bp_76(function: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let Some(body) = function.child_by_field_name("body") else {
        return;
    };

    let mut local_maps = HashSet::new();
    collect_local_maps(body, body, source, &mut local_maps);
    if local_maps.is_empty() {
        return;
    }

    find_unordered_outputs(body, body, source, unit, &local_maps, out);
}

fn collect_local_maps(node: Node, body: Node, source: &[u8], maps: &mut HashSet<String>) {
    if node.id() != body.id() && is_function(node) {
        return;
    }

    if matches!(
        node.kind(),
        "var_declaration" | "short_var_declaration" | "assignment_statement"
    ) {
        maps.extend(map_bindings(node, source));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_local_maps(child, body, source, maps);
    }
}

fn map_bindings(node: Node, source: &[u8]) -> Vec<String> {
    let Ok(text) = node.utf8_text(source) else {
        return Vec::new();
    };
    let text = text.trim();

    if let Some(rest) = text.strip_prefix("var ") {
        let mut parts = rest.split_whitespace();
        let name = parts.next().unwrap_or_default();
        let type_text = parts.next().unwrap_or_default();
        if is_identifier(name) && type_text.starts_with("map[") {
            return vec![name.to_owned()];
        }
    }

    let Some((left, right)) = text.split_once(":=").or_else(|| text.split_once('=')) else {
        return Vec::new();
    };
    let right = right.trim();
    if !(right.starts_with("map[") || right.starts_with("make(map")) {
        return Vec::new();
    }

    left.split(',')
        .map(str::trim)
        .filter(|name| is_identifier(name))
        .map(str::to_owned)
        .collect()
}

fn find_unordered_outputs(
    node: Node,
    body: Node,
    source: &[u8],
    unit: &ParsedUnit,
    local_maps: &HashSet<String>,
    out: &mut Vec<Finding>,
) {
    if node.id() != body.id() && is_function(node) {
        return;
    }

    if node.kind() == "range_clause"
        && let Some(map_name) = range_map_name(node, source)
        && local_maps.contains(map_name)
        && let Some(loop_body) = node
            .parent()
            .filter(|parent| parent.kind() == "for_statement")
            .and_then(|parent| parent.child_by_field_name("body"))
        && let Some(bindings) = range_bindings(node, source)
        && let Some((output, append_end)) =
            appended_range_value(loop_body, loop_body, source, &bindings)
        && let Some(join) = later_join(body, body, source, &output, append_end)
        && !sorted_between(body, body, source, &output, append_end, join.start_byte())
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_76_META,
            node.start_byte(),
            "map iteration feeds ordered output without sorting; collect keys or values and sort before strings.Join",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        find_unordered_outputs(child, body, source, unit, local_maps, out);
    }
}

fn range_map_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let right = node.child_by_field_name("right")?;
    let text = right.utf8_text(source).ok()?.trim();
    is_identifier(text).then_some(text)
}

struct RangeBindings {
    key: Option<String>,
    value: Option<String>,
}

fn range_bindings(node: Node, source: &[u8]) -> Option<RangeBindings> {
    let text = node.utf8_text(source).ok()?.trim();
    let (left, _) = text.split_once(":=").or_else(|| text.split_once('='))?;
    let names: Vec<&str> = left
        .split(',')
        .map(str::trim)
        .filter(|name| is_identifier(name))
        .collect();
    match names.as_slice() {
        [key] => Some(RangeBindings {
            key: (*key != "_").then(|| (*key).to_owned()),
            value: None,
        }),
        [key, value] => Some(RangeBindings {
            key: (*key != "_").then(|| (*key).to_owned()),
            value: (*value != "_").then(|| (*value).to_owned()),
        }),
        _ => None,
    }
}

fn appended_range_value(
    node: Node,
    body: Node,
    source: &[u8],
    bindings: &RangeBindings,
) -> Option<(String, usize)> {
    if node.id() != body.id() && is_function(node) {
        return None;
    }

    if node.kind() == "call_expression" && call_name(node, source) == Some("append") {
        let mut cursor = node.child_by_field_name("arguments")?.walk();
        let args: Vec<Node> = node
            .child_by_field_name("arguments")?
            .named_children(&mut cursor)
            .collect();
        if args.len() >= 2 {
            let output = args[0].utf8_text(source).ok()?.trim();
            let appended = args[1].utf8_text(source).ok()?.trim();
            if is_identifier(output)
                && (bindings.key.as_deref() == Some(appended)
                    || bindings.value.as_deref() == Some(appended))
            {
                return Some((output.to_owned(), node.end_byte()));
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = appended_range_value(child, body, source, bindings) {
            return Some(found);
        }
    }
    None
}

fn later_join<'a>(
    node: Node<'a>,
    body: Node<'a>,
    source: &'a [u8],
    output: &str,
    after: usize,
) -> Option<Node<'a>> {
    if node.id() != body.id() && is_function(node) {
        return None;
    }

    if node.kind() == "call_expression"
        && node.start_byte() > after
        && call_name(node, source) == Some("strings.Join")
        && first_argument_is(node, source, output)
    {
        return Some(node);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = later_join(child, body, source, output, after) {
            return Some(found);
        }
    }
    None
}

fn sorted_between(
    node: Node,
    body: Node,
    source: &[u8],
    output: &str,
    start: usize,
    end: usize,
) -> bool {
    if node.id() != body.id() && is_function(node) {
        return false;
    }

    if node.kind() == "call_expression"
        && node.start_byte() >= start
        && node.end_byte() <= end
        && matches!(
            call_name(node, source),
            Some("sort.Strings")
                | Some("sort.Ints")
                | Some("sort.Slice")
                | Some("slices.Sort")
                | Some("slices.SortFunc")
        )
        && first_argument_is(node, source, output)
    {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| sorted_between(child, body, source, output, start, end))
}

fn first_argument_is(node: Node, source: &[u8], expected: &str) -> bool {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .next()
        .and_then(|argument| argument.utf8_text(source).ok())
        .is_some_and(|text| text.trim() == expected)
}

/// BP-81: two or more clock reads in one condition can observe different
/// instants. The detector deliberately scopes the count to one condition, so
/// independent conditions in a function remain valid.
pub(crate) fn detect_bp_81_repeated_now_in_condition(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_conditions(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_conditions(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "if_statement"
        && let Some(condition) = node.child_by_field_name("condition")
        && count_time_now(condition, source) >= 2
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_81_META,
            condition.start_byte(),
            "condition reads time.Now more than once; capture one now value before comparing",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_conditions(child, source, unit, out);
    }
}

fn count_time_now(node: Node, source: &[u8]) -> usize {
    let own = usize::from(
        node.kind() == "call_expression" && call_name(node, source) == Some("time.Now"),
    );
    let mut cursor = node.walk();
    own + node
        .named_children(&mut cursor)
        .map(|child| count_time_now(child, source))
        .sum::<usize>()
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
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
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}
