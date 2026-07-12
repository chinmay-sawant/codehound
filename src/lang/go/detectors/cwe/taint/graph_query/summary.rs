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
use super::query::find_taint_paths_from_nodes_to_sink_argument;
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

/// Bounded multi-hop refinement of return-source summaries through a call graph.
///
/// If `A` calls `B` and `B` returns taint, mark `A` as return-tainted when
/// `A` returns `B`'s result (or always if `B` has a direct source). Iterates
/// up to `max_depth` times. Same-package only (caller provides file-local graph).
pub fn refine_summaries_multihop(
    call_graph: &super::super::CallGraph,
    summaries: &mut HashMap<String, TaintSummary>,
    max_depth: u32,
) {
    let depth = max_depth.clamp(1, 4);
    for _ in 1..depth {
        let mut changed = false;
        for site in &call_graph.sites {
            let caller = site.caller.as_ref();
            let callee = site.callee.as_ref();
            // Strip package prefix for method calls: `recv.Method` → `Method`
            let callee_key = callee.rsplit('.').next().unwrap_or(callee);
            let Some(callee_sum) = summaries.get(callee_key).cloned() else {
                continue;
            };
            let returns_taint =
                callee_sum.return_sources.iter().any(|b| *b) || callee_sum.has_direct_sink;
            if !returns_taint {
                continue;
            }
            let Some(caller_sum) = summaries.get_mut(caller) else {
                continue;
            };
            // Expand caller's return_sources if still false.
            if caller_sum.return_sources.iter().all(|b| !*b) {
                if caller_sum.return_sources.is_empty() {
                    caller_sum.return_sources.push(true);
                } else {
                    for b in &mut caller_sum.return_sources {
                        *b = true;
                    }
                }
                // Propagate sink kinds upward conservatively.
                for sk in &callee_sum.sink_kinds {
                    if !caller_sum.sink_kinds.contains(sk) {
                        caller_sum.sink_kinds.push(*sk);
                    }
                }
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
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
            let paths = if sink_kind == SinkKind::SQLQuery {
                find_taint_paths_from_nodes_to_sink_argument(
                    graph,
                    ids,
                    sink_kind,
                    0,
                    allowed_sanitizers,
                )
            } else {
                find_taint_paths_from_nodes(graph, ids, sink_kind, allowed_sanitizers)
            };
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
                    let paths = find_taint_paths_from_nodes(
                        graph,
                        source_ids,
                        sink_kind,
                        allowed_sanitizers,
                    );
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

    // Check output pointer params: `*T` params written to via `*p = source()`.
    let output_pointer_params =
        compute_output_pointer_params(annotations, source, func_name, params);

    TaintSummary {
        param_sources,
        return_sources,
        param_sanitizers,
        has_direct_sink,
        sink_kinds,
        output_pointer_params,
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
    _graph: &TaintGraph,
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
    let has_source_in_func = annotations
        .sources
        .iter()
        .any(|src| src.byte_range.start >= range.start && src.byte_range.end <= range.end);
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

/// Detect `*T` parameters that are written to via `*p = source_call()` in the
/// function body. These are "output pointer params" — taint written through
/// them leaks back to the caller's variable.
// ponytail: text-based `*param =` detection.  No type inference needed for
// the common case.  Full `*T` type detection + RHS source-call parsing could
// eliminate false positives on `*p = 42` (non-source write); add if needed.
fn compute_output_pointer_params(
    annotations: &TaintAnnotations,
    source: &str,
    func_name: &str,
    params: &[Arc<str>],
) -> Vec<usize> {
    let range = match annotations.function_ranges.get(func_name) {
        Some(r) => r.clone(),
        None => return Vec::new(),
    };
    let end = range.end.min(source.len());
    let start = range.start.min(end);
    let body = &source[start..end];

    // Check if the function body contains any source call at all.
    let has_source = annotations
        .sources
        .iter()
        .any(|s| s.byte_range.start >= range.start && s.byte_range.end <= range.end);
    if !has_source {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (i, param) in params.iter().enumerate() {
        let name = param.as_ref();
        // Look for `*{name} =` or `*{name}=` (dereference assignment).
        let needle1 = format!("*{name} =");
        let needle2 = format!("*{name}=");
        if body.contains(&needle1) || body.contains(&needle2) {
            out.push(i);
        }
    }
    out
}
