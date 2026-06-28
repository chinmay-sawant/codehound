use tree_sitter::Node;

use crate::ast::{walk_calls_and_assignments, walk_nodes};
use crate::core::ParsedUnit;
use crate::lang::go::CALL_ASSIGN_NODE_KINDS;

use super::super::source_index::PerfSourceIndex;
use super::classifier::{classify_init_only, collect_var_spec_kinds};
use super::text::{extract_identifiers, split_assignment};
use super::types::*;

pub fn build_go_perf_facts(unit: &ParsedUnit) -> GoPerfFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoPerfFacts::default();
    let mut interner = SharedTextInterner::default();

    walk_calls_and_assignments(root, CALL_ASSIGN_NODE_KINDS, &mut |node| match node.kind() {
        "call_expression" | "call" => {
            record_call_fact(node, &mut facts, src, &mut interner);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment_fact(node, &mut facts, src, &mut interner);
        }
        "defer_statement" | "go_statement" | "for_statement" | "type_assertion_expression" => {
            record_perf_node(node, &mut facts);
        }
        _ => {}
    });

    // Walk `var_spec` nodes to capture variables declared with an explicit
    // type (`var x int = 5`, `var s string`, `var buf []byte`). The explicit
    // type always wins; if the spec also has an initializer it is only used
    // as a fallback (e.g. `var x = 0.0`).
    walk_nodes(root, &["var_spec"], &mut |spec| {
        collect_var_spec_kinds(spec, src, &mut facts.var_kinds, &mut interner);
    });

    facts.source_index = PerfSourceIndex::build(unit.source.as_ref());
    facts
}

pub(crate) fn record_call_fact<'a>(
    node: Node,
    facts: &mut GoPerfFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(callee) = func.utf8_text(src) else {
        return;
    };

    let arguments = node
        .child_by_field_name("arguments")
        .map(|args| extract_argument_texts(args, src, interner))
        .unwrap_or_default();

    facts.calls.push(CallFact {
        callee: interner.intern(callee),
        arguments,
        start_byte: node.start_byte(),
        enclosing_loop: enclosing_loop_start(node),
    });
}

pub(crate) fn record_assignment_fact<'a>(
    node: Node,
    facts: &mut GoPerfFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Ok(text) = node.utf8_text(src) else {
        return;
    };
    let Some((lhs, rhs)) = split_assignment(text) else {
        return;
    };
    let is_short = text.contains(":=");
    for name in extract_identifiers(lhs) {
        if name.is_empty() {
            continue;
        }
        facts.assignments.push(AssignmentFact {
            name: interner.intern(name),
            expr: interner.intern(rhs),
            text: interner.intern(text),
            start_byte: node.start_byte(),
            enclosing_loop: enclosing_loop_start(node),
        });
        if is_short && !facts.var_kinds.contains_key(name) {
            if let Some(kind) = classify_init_only(rhs) {
                facts.var_kinds.insert(interner.intern(name), kind);
            }
        }
    }
}

pub(crate) fn record_perf_node(node: Node, facts: &mut GoPerfFacts) {
    match node.kind() {
        "defer_statement" => {
            facts
                .defer_starts
                .push((node.start_byte(), node.end_byte()));
        }
        "go_statement" => {
            facts.go_starts.push((node.start_byte(), node.end_byte()));
        }
        "for_statement" => {
            facts.for_ranges.push((node.start_byte(), node.end_byte()));
        }
        "type_assertion_expression" => {
            facts
                .type_assertions
                .push((node.start_byte(), node.end_byte()));
        }
        _ => {}
    }
}

/// Returns the start byte of the nearest enclosing `for_statement`, if any.
pub(crate) fn enclosing_loop_start(node: Node) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "for_statement" {
            return Some(parent.start_byte());
        }
        current = parent;
    }
    None
}

pub(crate) fn extract_argument_texts<'a>(
    args_node: tree_sitter::Node,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) -> Box<[SharedText]> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(interner.intern(text.trim()));
        }
    }
    out.into_boxed_slice()
}
