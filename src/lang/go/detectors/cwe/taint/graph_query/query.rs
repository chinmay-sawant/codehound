//! Taint path query: BFS through the `TaintGraph` to find sanitized /
//! unsanitized paths from any source of `source_kind` to any sink of
//! `sink_kind`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintGraph, TaintNode, TaintNodeId};

use super::TaintPath;

/// Find taint paths from any source of `source_kind` to any sink of `sink_kind`
/// within the same function scope. A path is "sanitized" if every path from the
/// source to the sink passes through an allowed sanitizer. If any unsanitized
/// path exists, the reported path is unsanitized.
pub fn find_taint_paths(
    graph: &TaintGraph,
    source_kind: SourceKind,
    sink_kind: SinkKind,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let source_ids: Vec<TaintNodeId> = graph
        .by_source
        .get(&source_kind)
        .cloned()
        .unwrap_or_default();
    let sink_ids: Vec<TaintNodeId> = graph.by_sink.get(&sink_kind).cloned().unwrap_or_default();

    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path(graph, &source_ids, sink_id, allowed_sanitizers) {
            paths.push(path);
        }
    }
    paths
}

/// Find taint paths from arbitrary start node IDs to sinks of `sink_kind`.
pub fn find_taint_paths_from_nodes(
    graph: &TaintGraph,
    start_ids: &[TaintNodeId],
    sink_kind: SinkKind,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let sink_ids: Vec<TaintNodeId> = graph.by_sink.get(&sink_kind).cloned().unwrap_or_default();
    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path(graph, start_ids, sink_id, allowed_sanitizers) {
            paths.push(path);
        }
    }
    paths
}

fn bfs_path(
    graph: &TaintGraph,
    source_ids: &[TaintNodeId],
    sink_id: TaintNodeId,
    allowed_sanitizers: &[SanitizerKind],
) -> Option<TaintPath> {
    // Build adjacency list for forward traversal.
    let mut adj: HashMap<TaintNodeId, Vec<TaintNodeId>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from).or_default().push(edge.to);
    }

    // State: (node, sanitized) -> visited. We want to find an unsanitized path
    // first; if none exists, accept a sanitized path.
    let mut queue: VecDeque<(TaintNodeId, bool, Vec<TaintNodeId>)> = VecDeque::new();
    let mut visited: HashSet<(TaintNodeId, bool)> = HashSet::new();

    for &source_id in source_ids {
        let sanitized = is_sanitizer(graph, source_id, allowed_sanitizers);
        queue.push_back((source_id, sanitized, vec![source_id]));
        visited.insert((source_id, sanitized));
    }

    let mut best_sanitized_path: Option<Vec<TaintNodeId>> = None;

    while let Some((current, sanitized, path)) = queue.pop_front() {
        if current == sink_id {
            if !sanitized {
                return Some(TaintPath {
                    source_id: path[0],
                    sink_id,
                    node_ids: path,
                    sanitized: false,
                });
            }
            if best_sanitized_path.is_none() {
                best_sanitized_path = Some(path.clone());
            }
            continue;
        }

        for &next in adj.get(&current).unwrap_or(&Vec::new()) {
            let next_sanitized = sanitized || is_sanitizer(graph, next, allowed_sanitizers);
            if visited.insert((next, next_sanitized)) {
                let mut next_path = path.clone();
                next_path.push(next);
                queue.push_back((next, next_sanitized, next_path));
            }
        }
    }

    best_sanitized_path.map(|path| TaintPath {
        source_id: path[0],
        sink_id,
        node_ids: path,
        sanitized: true,
    })
}

pub(super) fn is_sanitizer(
    graph: &TaintGraph,
    node_id: TaintNodeId,
    allowed: &[SanitizerKind],
) -> bool {
    matches!(
        graph.nodes.get(node_id),
        Some(TaintNode::Sanitizer { kind, .. }) if allowed.contains(kind)
    )
}
