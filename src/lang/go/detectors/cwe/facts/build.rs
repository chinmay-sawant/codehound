//! `build_go_unit_facts` + `build_taint_graph_for_facts`.

use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::CALL_ASSIGN_NODE_KINDS;

use super::super::source_index::{NEEDLES, SourceIndex};
use super::super::taint::{build_taint_graph, extract_call_graph, extract_taint_facts};
use super::interner::{SharedTextInterner, record_assignment_fact, record_call_fact};
use super::types::GoUnitFacts;

/// What expensive extractions to run for a unit.
///
/// Structural detectors need the tree walk + `SourceIndex`. Taint annotations
/// and call graphs are only required when inter-procedural taint is on.
#[derive(Debug, Clone, Copy)]
pub struct FactBuildOpts {
    pub extract_structural: bool,
    pub extract_taint: bool,
    pub extract_call_graph: bool,
}

impl Default for FactBuildOpts {
    fn default() -> Self {
        Self {
            extract_structural: true,
            extract_taint: true,
            extract_call_graph: true,
        }
    }
}

impl FactBuildOpts {
    /// Cheap structural facts only (no taint annotations / call graph).
    pub const STRUCTURAL: Self = Self {
        extract_structural: true,
        extract_taint: false,
        extract_call_graph: false,
    };

    /// Full facts for taint-enabled scans.
    pub const TAINT: Self = Self {
        extract_structural: true,
        extract_taint: true,
        extract_call_graph: true,
    };

    /// Taint graph and call graph only. Used by narrow taint-only scans whose
    /// selected rules do not inspect structural calls, assignments, or needles.
    pub const TAINT_ONLY: Self = Self {
        extract_structural: false,
        extract_taint: true,
        extract_call_graph: true,
    };

    /// No selected rule needs facts. Keeps disabled taint-only `--only` scans
    /// from paying for the structural bundle merely to produce no findings.
    pub const NONE: Self = Self {
        extract_structural: false,
        extract_taint: false,
        extract_call_graph: false,
    };

    // ponytail: unit/integration proofs cover unused-bundle skip; full
    // release-bench compare of default vs `--only` alloc/throughput is still
    // the upgrade path when measuring cache locality of matcher tables.

    pub fn for_scan(taint_enabled: bool, extract_structural: bool) -> Self {
        if taint_enabled && !extract_structural {
            Self::TAINT_ONLY
        } else if taint_enabled {
            Self::TAINT
        } else if !extract_structural {
            Self::NONE
        } else {
            Self::STRUCTURAL
        }
    }
}

pub fn build_go_unit_facts(unit: &ParsedUnit) -> GoUnitFacts {
    build_go_unit_facts_with(unit, FactBuildOpts::default())
}

pub fn build_go_unit_facts_with(unit: &ParsedUnit, opts: FactBuildOpts) -> GoUnitFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoUnitFacts::default();
    let mut interner = SharedTextInterner::default();

    if opts.extract_structural {
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
    }
    if opts.extract_taint {
        facts.taint = extract_taint_facts(unit);
    }
    if opts.extract_call_graph {
        facts.call_graph = Some(extract_call_graph(unit));
    }
    facts
}

/// Build the intra-procedural taint graph from already-extracted facts.
/// Callers should only do this when `[taint] enabled = true`.
pub fn build_taint_graph_for_facts(facts: &mut GoUnitFacts) {
    facts.taint_graph = Some(build_taint_graph(&facts.taint));
}
