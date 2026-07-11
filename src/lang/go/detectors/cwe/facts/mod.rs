//! Fact extraction for Go CWE heuristics.
//!
//! These types are internal to the Go CWE detector bundle. Library consumers
//! see only the `Finding` they produce; the IR lives behind `pub(crate)`.

mod build;
mod input_classify;
mod interner;
mod types;

pub use crate::lang::assignment::{extract_identifiers, split_assignment};
pub use build::{
    FactBuildOpts, build_go_unit_facts, build_go_unit_facts_with, build_taint_graph_for_facts,
};
pub use input_classify::{is_trusted_config_expr, is_user_input_expr};
pub use types::{AssignmentFact, CallFact, GoUnitFacts, InputBinding, InputKind, SharedText};
