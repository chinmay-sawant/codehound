//! Function-level taint summaries for inter-procedural propagation.
//!
//! For each function that appears as a callee in the project call graph,
//! compute a `TaintSummary` that captures:
//! - Which parameters are taint sources (reach a sink)
//! - Which return values carry taint
//! - Which parameters are sanitized before reaching a sink
//! - Direct sinks called unconditionally

use std::collections::HashMap;
use std::sync::Arc;

use super::super::{
    SanitizerKind, SinkKind, SourceKind, TaintAnnotations, TaintGraph, TaintNode, TaintNodeId,
    TaintSummary,
};
use super::{build_taint_graph, find_taint_paths_from_nodes};

/// Build per-function taint summaries for all functions annotated in the
/// project call graph. Returns (function_name → TaintSummary).
pub fn compute_all_summaries(
    annotations: &TaintAnnotations,
    source: &str,
) -> HashMap<String, TaintSummary> {
    let graph = build_taint_graph(annotations);
    let mut summaries: HashMap<String, TaintSummary> = HashMap::new();

    for (func_name, params) in &annotations.function_params {
        let summary = compute_summary_for(&graph, annotations, source, func_name, params);
        summaries.insert(func_name.to_string(), summary);
    }

    summaries
}

/// Compute a `TaintSummary` for one function.
fn compute_summary_for(
    graph: &TaintGraph,
    annotations: &TaintAnnotations,
    source: &str,
    func_name: &str,
    params: &[Arc<str>],
) -> TaintSummary {
    // Find all variable nodes in the graph that match each parameter name.
    let mut param_node_ids: Vec<Vec<TaintNodeId>> = Vec::new();
    for param in params {
        let ids: Vec<TaintNodeId> = graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| matches!(n, TaintNode::Variable { name, .. } if name.as_ref() == param.as_ref()))
            .map(|(id, _)| id)
            .collect();
        param_node_ids.push(ids);
    }

    // Check all sink kinds — if any parameter reaches a sink, mark it.
    let all_sink_kinds = [
        SinkKind::CommandExec,
        SinkKind::SQLQuery,
        SinkKind::FileOpen,
        SinkKind::Template,
        SinkKind::HTTPWrite,
        SinkKind::Deserialization,
        SinkKind::LDAPQuery,
        SinkKind::XMLQuery,
    ];

    let allowed_sanitizers: &[SanitizerKind] = &[];

    let mut param_sources: Vec<Option<bool>> = Vec::new();
    let mut param_sanitizers: Vec<(usize, SanitizerKind)> = Vec::new();
    let mut sink_kinds: Vec<SinkKind> = Vec::new();
    let mut has_direct_sink = false;

    for (i, ids) in param_node_ids.iter().enumerate() {
        let mut reaches_sink = false;

        for &sink_kind in &all_sink_kinds {
            if ids.is_empty() {
                continue;
            }
            let paths = find_taint_paths_from_nodes(graph, ids, sink_kind, allowed_sanitizers);
            if !paths.is_empty() {
                reaches_sink = true;
                if !sink_kinds.contains(&sink_kind) {
                    sink_kinds.push(sink_kind);
                }
                // Check if any path is sanitized.
                for path in &paths {
                    if path.sanitized {
                        // ponytail: exact sanitizer kind detection deferred.
                        param_sanitizers.push((i, SanitizerKind::Validation));
                    }
                }
            }
        }

        if reaches_sink {
            param_sources.push(Some(true));
        } else {
            param_sources.push(Some(false));
        }
    }

    // Check for direct sinks (sinks reachable without any parameter).
    // A direct sink is one where the path starts at a source node (not a param).
    if has_any_source(graph) {
        has_direct_sink = true;
        for &sink_kind in &all_sink_kinds {
            if !graph.by_sink.contains_key(&sink_kind) {
                continue;
            }
            if !sink_kinds.contains(&sink_kind) {
                // Check if source nodes reach any sink directly.
                if let Some(source_ids) = graph.by_source.get(&SourceKind::UserInput) {
                    let paths = find_taint_paths_from_nodes(graph, source_ids, sink_kind, allowed_sanitizers);
                    if !paths.is_empty() && !sink_kinds.contains(&sink_kind) {
                        sink_kinds.push(sink_kind);
                    }
                }
            }
        }
    }

    // Check return values: scan for return_statement nodes and check if any
    // referenced variable has a taint path from a source.
    let return_sources = compute_return_sources(graph, annotations, source, func_name);

    TaintSummary {
        param_sources,
        return_sources,
        param_sanitizers,
        has_direct_sink,
        sink_kinds,
    }
}

/// Check if the graph has any source nodes.
fn has_any_source(graph: &TaintGraph) -> bool {
    !graph.by_source.is_empty()
}

/// Determine whether this function returns tainted data.
///
/// Returns true if the function has a source within its body, OR if the
/// function returns one of its parameters (parameter-to-return propagation).
fn compute_return_sources(
    graph: &TaintGraph,
    annotations: &TaintAnnotations,
    source: &str,
    func_name: &str,
) -> Vec<bool> {
    // Get this function's byte range.
    let range = annotations.function_ranges.get(func_name);
    let Some(range) = range else {
        return vec![false];
    };

    // Check 1: Does the function have a source within its body?
    let has_source_in_func = annotations.sources.iter().any(|src| {
        src.byte_range.start >= range.start && src.byte_range.end <= range.end
    });
    if has_source_in_func {
        return vec![true];
    }

    // Check 2: Does the function return a parameter?
    // (param-to-return propagation: `return s` where s is a parameter)
    let params = annotations.function_params.get(func_name);
    if let Some(params) = params {
        let end = range.end.min(source.len());
        let start = range.start.min(end);
        let body = &source[start..end];
        for param in params {
            // Scan for `return param_name` in the function body.
            let pattern = format!("return {}", param);
            if body.contains(&pattern) {
                return vec![true];
            }
        }
    }

    vec![false]
}
