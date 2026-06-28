//! Fact extraction for Go CWE heuristics.
//!
//! These types are internal to the Go CWE detector bundle. Library consumers
//! see only the `Finding` they produce; the IR lives behind `pub(crate)`.

mod build;
mod expr_patterns;
mod interner;
mod types;

pub use build::{build_go_unit_facts, build_taint_graph_for_facts};
pub use expr_patterns::{
    extract_identifiers, is_trusted_config_expr, is_user_input_expr, split_assignment,
};
pub use types::{AssignmentFact, CallFact, GoUnitFacts, InputBinding, InputKind, SharedText};
