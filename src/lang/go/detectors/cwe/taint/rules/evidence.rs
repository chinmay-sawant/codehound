//! Shared `variable_name_at` + `source_info` helpers used by the four
//! `detect_cwe_*_taint` rules.

use crate::rules::TaintSourceInfo;

use super::super::{EdgeKind, TaintGraph, TaintNode, TaintPath};

pub(super) fn variable_name_at(graph: &TaintGraph, node_id: usize) -> Option<String> {
    match graph.nodes.get(node_id)? {
        TaintNode::Variable { name, .. } => Some(name.to_string()),
        TaintNode::Source { .. } => {
            // Find an outgoing assignment edge to a variable.
            graph
                .edges
                .iter()
                .find(|e| e.from == node_id && matches!(e.kind, EdgeKind::Assignment))
                .and_then(|e| variable_name_at(graph, e.to))
        }
        _ => None,
    }
}

pub(super) fn source_info(graph: &TaintGraph, path: &TaintPath) -> TaintSourceInfo {
    let function = match graph.nodes.get(path.source_id) {
        Some(TaintNode::Source { function, .. }) => function.to_string(),
        _ => "unknown".to_string(),
    };
    TaintSourceInfo {
        kind: "UserInput".to_string(),
        function,
        variable: variable_name_at(graph, path.source_id).unwrap_or_default(),
    }
}
