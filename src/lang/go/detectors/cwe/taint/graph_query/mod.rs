//! Build and query the intra-procedural taint graph.

mod build;
mod query;
mod summary;
#[cfg(test)]
mod tests;

use crate::lang::go::detectors::cwe::taint::TaintNodeId;

/// A discovered taint path from a source to a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintPath {
    pub source_id: TaintNodeId,
    pub sink_id: TaintNodeId,
    pub node_ids: Vec<TaintNodeId>,
    pub sanitized: bool,
}

pub use build::build_taint_graph;
pub use query::{
    find_taint_paths, find_taint_paths_from_nodes, forward_reaches_any, unsanitized_reaches_any,
};
pub use summary::{compute_all_summaries, refine_summaries_multihop};
