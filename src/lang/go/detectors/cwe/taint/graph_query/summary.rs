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

use super::super::{SinkKind, TaintAnnotations, TaintGraph, TaintNode, TaintNodeId, TaintSummary};
use super::query::{
    TaintGraphIndex, build_index, reaches_sink_argument_from_nodes_with_adj,
    reaches_sink_from_nodes_with_adj,
};

/// Build per-function taint summaries for all functions annotated in the
/// project call graph. Returns (function_name → TaintSummary).
pub fn compute_all_summaries(
    annotations: &TaintAnnotations,
    source: &str,
) -> HashMap<String, TaintSummary> {
    let graph = super::build_taint_graph(annotations);
    compute_all_summaries_with_graph(&graph, annotations, source)
}

/// Build summaries from a graph that was already constructed for the same
/// annotations. Production finalization uses this to avoid rebuilding the
/// per-file graph after per-file rules have already queried it.
pub fn compute_all_summaries_with_graph(
    graph: &TaintGraph,
    annotations: &TaintAnnotations,
    source: &str,
) -> HashMap<String, TaintSummary> {
    let index = build_index(graph);
    compute_all_summaries_with_graph_and_index(graph, &index, annotations, source)
}

/// Build summaries with a caller-owned graph index so summary construction and
/// the following inter-procedural query phase share the same adjacency map.
pub(crate) fn compute_all_summaries_with_graph_and_index(
    graph: &TaintGraph,
    index: &TaintGraphIndex,
    annotations: &TaintAnnotations,
    source: &str,
) -> HashMap<String, TaintSummary> {
    let mut summaries: HashMap<String, TaintSummary> = HashMap::new();

    for (func_name, params) in &annotations.function_params {
        let summary = compute_summary_for(graph, index, annotations, source, func_name, params);
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
    refine_summaries_inner(call_graph, None, summaries, max_depth);
}

/// Refine summaries with the caller's parameter names so taint can cross a
/// direct parameter-to-parameter call without treating same-named variables
/// in unrelated functions as one graph node.
pub fn refine_summaries_multihop_with_context(
    call_graph: &super::super::CallGraph,
    annotations: &TaintAnnotations,
    summaries: &mut HashMap<String, TaintSummary>,
    max_depth: u32,
) {
    refine_summaries_inner(call_graph, Some(annotations), summaries, max_depth);
}

fn refine_summaries_inner(
    call_graph: &super::super::CallGraph,
    annotations: Option<&TaintAnnotations>,
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
            let Some(caller_sum) = summaries.get_mut(caller) else {
                continue;
            };

            if let Some(annotations) = annotations {
                let Some(caller_params) = annotations.function_params.get(caller) else {
                    continue;
                };
                for (callee_idx, is_source) in callee_sum.param_sources.iter().enumerate() {
                    if !matches!(is_source, Some(true)) {
                        continue;
                    }
                    let Some(argument) = site.arguments.get(callee_idx) else {
                        continue;
                    };
                    let argument = argument.as_ref();
                    let argument = argument
                        .strip_prefix('&')
                        .map(str::trim)
                        .unwrap_or(argument);
                    let Some(caller_idx) = caller_params
                        .iter()
                        .position(|param| param.as_ref() == argument)
                    else {
                        continue;
                    };
                    if caller_sum.param_sources.len() <= caller_idx {
                        caller_sum.param_sources.resize(caller_idx + 1, Some(false));
                    }
                    if caller_sum.param_sources[caller_idx] != Some(true) {
                        caller_sum.param_sources[caller_idx] = Some(true);
                        changed = true;
                    }
                    for sink_kind in &callee_sum.sink_kinds {
                        if !caller_sum.sink_kinds.contains(sink_kind) {
                            caller_sum.sink_kinds.push(*sink_kind);
                        }
                    }
                }
            }

            if !site.returns_result {
                continue;
            }
            let returns_taint = callee_sum.return_sources.iter().any(|b| *b);
            if !returns_taint {
                continue;
            }
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
    index: &super::query::TaintGraphIndex,
    annotations: &TaintAnnotations,
    source: &str,
    func_name: &str,
    params: &[Arc<str>],
) -> TaintSummary {
    let adj = index.adjacency();

    // Find all variable nodes in the graph that match each parameter name.
    let mut param_node_ids: Vec<Vec<TaintNodeId>> = Vec::new();
    for param in params {
        let ids: Vec<TaintNodeId> = graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(id, n)| {
                matches!(n, TaintNode::Variable { name, .. } if name.as_ref() == param.as_ref())
                    && node_in_function(graph, *id, annotations, func_name)
            })
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

    let mut param_sources: Vec<Option<bool>> = Vec::new();
    let mut sink_kinds: Vec<SinkKind> = Vec::new();
    let mut has_direct_sink = false;

    for ids in &param_node_ids {
        let mut reaches_sink = false;

        for &sink_kind in &all_sink_kinds {
            if ids.is_empty() {
                continue;
            }
            let reaches = if sink_kind == SinkKind::SQLQuery {
                reaches_sink_argument_from_nodes_with_adj(graph, adj, ids, sink_kind, 0)
            } else {
                reaches_sink_from_nodes_with_adj(graph, adj, ids, sink_kind)
            };
            if reaches {
                reaches_sink = true;
                if !sink_kinds.contains(&sink_kind) {
                    sink_kinds.push(sink_kind);
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
    let source_ids: Vec<TaintNodeId> = graph
        .by_source
        .values()
        .flatten()
        .copied()
        .filter(|id| node_in_function(graph, *id, annotations, func_name))
        .collect();
    if !source_ids.is_empty() {
        for &sink_kind in &all_sink_kinds {
            if !graph.by_sink.contains_key(&sink_kind) {
                continue;
            }
            if reaches_sink_from_nodes_with_adj(graph, adj, &source_ids, sink_kind) {
                has_direct_sink = true;
                if !sink_kinds.contains(&sink_kind) {
                    sink_kinds.push(sink_kind);
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
        param_sanitizers: Vec::new(),
        has_direct_sink,
        sink_kinds,
        output_pointer_params,
    }
}

fn node_in_function(
    graph: &TaintGraph,
    node_id: TaintNodeId,
    annotations: &TaintAnnotations,
    func_name: &str,
) -> bool {
    let Some(range) = annotations.function_ranges.get(func_name) else {
        return false;
    };
    let Some(node) = graph.nodes.get(node_id) else {
        return false;
    };
    match node {
        TaintNode::Variable { scope, .. } => annotations
            .scopes
            .iter()
            .find(|info| info.id == *scope)
            .and_then(|info| info.function.as_deref())
            .is_some_and(|function| function == func_name),
        TaintNode::Source { byte_range, .. }
        | TaintNode::Sink { byte_range, .. }
        | TaintNode::Sanitizer { byte_range, .. } => {
            byte_range.start >= range.start && byte_range.end <= range.end
        }
        TaintNode::Return { function, .. } => function.as_ref() == func_name,
    }
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

    // Check 1: Does the function return a source produced in its body?
    let has_returned_source = annotations
        .sources
        .iter()
        .filter(|src| src.byte_range.start >= range.start && src.byte_range.end <= range.end)
        .any(|src| source_is_returned(src, source, range));
    if has_returned_source {
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
            if body.lines().any(|line| {
                let Some(rest) = line.trim_start().strip_prefix("return") else {
                    return false;
                };
                rest.trim_start()
                    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .next()
                    == Some(param.as_ref())
            }) {
                return vec![true];
            }
        }
    }

    vec![false]
}

fn source_is_returned(
    source_annotation: &super::super::TaintSourceAnnotation,
    source: &str,
    function_range: &std::ops::Range<usize>,
) -> bool {
    let start = function_range.start.min(source.len());
    let end = function_range.end.min(source.len());
    let body = &source[start..end];
    let source_start = source_annotation.byte_range.start.saturating_sub(start);
    let source_end = source_annotation.byte_range.end.saturating_sub(start);
    let source_end = source_end.min(body.len());
    let source_start = source_start.min(source_end);

    let line_start = body[..source_start].rfind('\n').map_or(0, |idx| idx + 1);
    let line_end = body[source_end..]
        .find('\n')
        .map_or(body.len(), |idx| source_end + idx);
    if body[line_start..line_end].contains("return") {
        return true;
    }

    let Some(result_variable) = source_annotation.result_variable.as_deref() else {
        return false;
    };
    body.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix("return") else {
            return false;
        };
        let returned_name = rest
            .trim_start()
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .next();
        returned_name == Some(result_variable)
    })
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
