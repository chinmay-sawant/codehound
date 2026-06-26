//! Build and query the intra-procedural taint graph.

mod build;
mod query;
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
pub use query::find_taint_paths;
