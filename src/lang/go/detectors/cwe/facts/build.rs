//! `build_go_unit_facts` + `build_taint_graph_for_facts`.

use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::CALL_ASSIGN_NODE_KINDS;

use super::super::source_index::{NEEDLES, SourceIndex};
use super::super::taint::{build_taint_graph, extract_call_graph, extract_taint_facts};
use super::interner::{SharedTextInterner, record_assignment_fact, record_call_fact};
use super::types::GoUnitFacts;

pub fn build_go_unit_facts(unit: &ParsedUnit) -> GoUnitFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoUnitFacts::default();
    let mut interner = SharedTextInterner::default();

    walk_nodes(
        root,
        CALL_ASSIGN_NODE_KINDS,
        &mut |node| match node.kind() {
            "call_expression" | "call" => {
                record_call_fact(node, &mut facts, src, &mut interner);
            }
            "assignment_statement" | "short_var_declaration" => {
                record_assignment_fact(node, &mut facts, src, &mut interner);
            }
            _ => {}
        },
    );

    facts.source_index = SourceIndex::build(NEEDLES, unit.source.as_ref());
    facts.taint = extract_taint_facts(unit);
    facts.call_graph = Some(extract_call_graph(unit));
    facts
}

/// Build the intra-procedural taint graph from already-extracted facts.
/// Callers should only do this when `[taint] enabled = true`.
pub fn build_taint_graph_for_facts(facts: &mut GoUnitFacts) {
    facts.taint_graph = Some(build_taint_graph(&facts.taint));
}
