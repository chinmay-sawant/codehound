//! Taint path query: BFS through the `TaintGraph` to find sanitized /
//! unsanitized paths from any source of `source_kind` to any sink of
//! `sink_kind`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::super::{
    EdgeKind, SanitizerKind, SinkKind, SourceKind, TaintGraph, TaintNode, TaintNodeId,
};

use super::TaintPath;

type Adjacency = HashMap<TaintNodeId, Vec<(TaintNodeId, EdgeKind)>>;

pub(crate) struct TaintGraphIndex {
    adjacency: Adjacency,
}

impl TaintGraphIndex {
    pub(crate) fn adjacency(&self) -> &Adjacency {
        &self.adjacency
    }
}

pub(crate) fn build_index(graph: &TaintGraph) -> TaintGraphIndex {
    let mut adj: Adjacency = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from).or_default().push((edge.to, edge.kind));
    }
    TaintGraphIndex { adjacency: adj }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SearchState {
    node: TaintNodeId,
    sanitized: bool,
}

fn reconstruct_path(
    predecessors: &HashMap<SearchState, Option<SearchState>>,
    terminal: SearchState,
) -> Vec<TaintNodeId> {
    let mut path = Vec::new();
    let mut current = terminal;
    path.push(current.node);
    while let Some(Some(parent)) = predecessors.get(&current) {
        current = *parent;
        path.push(current.node);
    }
    path.reverse();
    path
}

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
    let source_ids = graph
        .by_source
        .get(&source_kind)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let sink_ids = graph
        .by_sink
        .get(&sink_kind)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let index = build_index(graph);

    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path(
            graph,
            index.adjacency(),
            source_ids,
            *sink_id,
            allowed_sanitizers,
        ) {
            paths.push(path);
        }
    }
    paths
}

/// Find taint paths from arbitrary start node IDs to sinks of `sink_kind`.
/// Forward BFS: returns true if any node in `targets` is reachable from any node in `starts`.
pub fn forward_reaches_any(
    graph: &TaintGraph,
    starts: &[TaintNodeId],
    targets: &[TaintNodeId],
) -> bool {
    if starts.is_empty() || targets.is_empty() {
        return false;
    }
    let index = build_index(graph);
    forward_reaches_any_with_index(graph, index.adjacency(), starts, targets)
}

pub(crate) fn forward_reaches_any_with_index(
    graph: &TaintGraph,
    adj: &Adjacency,
    starts: &[TaintNodeId],
    targets: &[TaintNodeId],
) -> bool {
    if starts.is_empty() || targets.is_empty() {
        return false;
    }
    let mut visited = vec![false; graph.nodes.len()];
    let mut queue: VecDeque<TaintNodeId> = VecDeque::new();
    for &start in starts {
        if start < visited.len() && !visited[start] {
            visited[start] = true;
            queue.push_back(start);
        }
    }
    while let Some(current) = queue.pop_front() {
        if targets.contains(&current) {
            return true;
        }
        for &(next, _) in adj.get(&current).into_iter().flatten() {
            if next < visited.len() && !visited[next] {
                visited[next] = true;
                queue.push_back(next);
            }
        }
    }
    false
}

/// BFS with sanitizer tracking: any `TaintNode::Sanitizer` on the path counts as sanitized.
/// Returns true only if an unsanitized path exists from `start` to any `target`.
pub fn unsanitized_reaches_any(
    graph: &TaintGraph,
    start: TaintNodeId,
    targets: &[TaintNodeId],
) -> bool {
    let index = build_index(graph);
    unsanitized_reaches_any_with_index(graph, index.adjacency(), start, targets)
}

pub(crate) fn unsanitized_reaches_any_with_index(
    graph: &TaintGraph,
    adj: &Adjacency,
    start: TaintNodeId,
    targets: &[TaintNodeId],
) -> bool {
    let mut queue: VecDeque<(TaintNodeId, bool)> = VecDeque::new();
    // Sanitizer state is part of the search state. Reaching a merge node via
    // a sanitized branch must not prevent a later unsanitized branch from
    // reaching the same node.
    let mut visited = HashSet::new();
    queue.push_back((start, false));
    visited.insert((start, false));

    while let Some((current, was_sanitized)) = queue.pop_front() {
        let sanitized =
            was_sanitized || matches!(graph.nodes.get(current), Some(TaintNode::Sanitizer { .. }));

        if targets.contains(&current) && !sanitized {
            return true;
        }

        for &(next, _) in adj.get(&current).into_iter().flatten() {
            let state = (next, sanitized);
            if next < graph.nodes.len() && visited.insert(state) {
                queue.push_back((next, sanitized));
            }
        }
    }
    false
}

pub fn find_taint_paths_from_nodes(
    graph: &TaintGraph,
    start_ids: &[TaintNodeId],
    sink_kind: SinkKind,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let index = build_index(graph);
    find_taint_paths_from_nodes_with_adj(
        graph,
        index.adjacency(),
        start_ids,
        sink_kind,
        allowed_sanitizers,
    )
}

pub(super) fn find_taint_paths_from_nodes_with_adj(
    graph: &TaintGraph,
    adj: &Adjacency,
    start_ids: &[TaintNodeId],
    sink_kind: SinkKind,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let sink_ids = graph
        .by_sink
        .get(&sink_kind)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path(graph, adj, start_ids, *sink_id, allowed_sanitizers) {
            paths.push(path);
        }
    }
    paths
}

pub(super) fn find_taint_paths_from_nodes_to_sink_argument_with_adj(
    graph: &TaintGraph,
    adj: &Adjacency,
    start_ids: &[TaintNodeId],
    sink_kind: SinkKind,
    sink_argument_index: usize,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let sink_ids = graph
        .by_sink
        .get(&sink_kind)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path_to_sink_argument(
            graph,
            adj,
            start_ids,
            *sink_id,
            sink_argument_index,
            allowed_sanitizers,
        ) {
            paths.push(path);
        }
    }
    paths
}

fn bfs_path(
    graph: &TaintGraph,
    adj: &Adjacency,
    source_ids: &[TaintNodeId],
    sink_id: TaintNodeId,
    allowed_sanitizers: &[SanitizerKind],
) -> Option<TaintPath> {
    // State: (node, sanitized) -> predecessor. Keeping sanitizer state in the
    // key preserves unsanitized branches while avoiding path cloning per edge.
    let mut queue: VecDeque<SearchState> = VecDeque::new();
    let mut predecessors: HashMap<SearchState, Option<SearchState>> = HashMap::new();

    for &source_id in source_ids {
        let sanitized = is_sanitizer(graph, source_id, allowed_sanitizers);
        let state = SearchState {
            node: source_id,
            sanitized,
        };
        queue.push_back(state);
        predecessors.insert(state, None);
    }

    let mut best_sanitized: Option<SearchState> = None;

    while let Some(current) = queue.pop_front() {
        if current.node == sink_id {
            if !current.sanitized {
                let path = reconstruct_path(&predecessors, current);
                return Some(TaintPath {
                    source_id: path[0],
                    sink_id,
                    node_ids: path,
                    sanitized: false,
                });
            }
            if best_sanitized.is_none() {
                best_sanitized = Some(current);
            }
            continue;
        }

        for &(next, _) in adj.get(&current.node).into_iter().flatten() {
            let next_state = SearchState {
                node: next,
                sanitized: current.sanitized || is_sanitizer(graph, next, allowed_sanitizers),
            };
            if next < graph.nodes.len() && !predecessors.contains_key(&next_state) {
                predecessors.insert(next_state, Some(current));
                queue.push_back(next_state);
            }
        }
    }

    best_sanitized.map(|terminal| {
        let path = reconstruct_path(&predecessors, terminal);
        TaintPath {
            source_id: path[0],
            sink_id,
            node_ids: path,
            sanitized: true,
        }
    })
}

fn bfs_path_to_sink_argument(
    graph: &TaintGraph,
    adj: &Adjacency,
    source_ids: &[TaintNodeId],
    sink_id: TaintNodeId,
    sink_argument_index: usize,
    allowed_sanitizers: &[SanitizerKind],
) -> Option<TaintPath> {
    let mut queue: VecDeque<SearchState> = VecDeque::new();
    let mut predecessors: HashMap<SearchState, Option<SearchState>> = HashMap::new();

    for &source_id in source_ids {
        let sanitized = is_sanitizer(graph, source_id, allowed_sanitizers);
        let state = SearchState {
            node: source_id,
            sanitized,
        };
        queue.push_back(state);
        predecessors.insert(state, None);
    }

    let mut best_sanitized: Option<SearchState> = None;

    while let Some(current) = queue.pop_front() {
        for &(next, edge_kind) in adj.get(&current.node).into_iter().flatten() {
            let next_state = SearchState {
                node: next,
                sanitized: current.sanitized || is_sanitizer(graph, next, allowed_sanitizers),
            };
            if next == sink_id {
                if !matches!(edge_kind, EdgeKind::Argument(idx) if idx == sink_argument_index) {
                    continue;
                }
                predecessors.insert(next_state, Some(current));
                if !next_state.sanitized {
                    let path = reconstruct_path(&predecessors, next_state);
                    return Some(TaintPath {
                        source_id: path[0],
                        sink_id,
                        node_ids: path,
                        sanitized: false,
                    });
                }
                if best_sanitized.is_none() {
                    best_sanitized = Some(next_state);
                }
                continue;
            }

            if next < graph.nodes.len() && !predecessors.contains_key(&next_state) {
                predecessors.insert(next_state, Some(current));
                queue.push_back(next_state);
            }
        }
    }

    best_sanitized.map(|terminal| {
        let path = reconstruct_path(&predecessors, terminal);
        TaintPath {
            source_id: path[0],
            sink_id,
            node_ids: path,
            sanitized: true,
        }
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
