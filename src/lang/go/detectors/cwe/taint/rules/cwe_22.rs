//! Detect CWE-22 (Path Traversal) via taint flow.

use crate::core::ParsedUnit;
use crate::engine::scratch_contains;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_22;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo};

use super::super::{
    EdgeKind, SanitizerKind, SinkKind, SourceKind, TaintGraph, TaintNode, TaintPath,
    find_taint_paths,
};
use super::evidence::source_info;

pub fn detect_cwe_22_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::FileOpen,
        &[SanitizerKind::Path],
    );

    for path in paths {
        if path.sanitized {
            continue;
        }

        // ponytail: substring-level confinement check (filepath.Abs + strings.HasPrefix)
        // matches the old substring detector's is_path_confined. Taint graph doesn't
        // model control-flow guards, so we fall back to scanning source. Upgrade: when a
        // proper control-flow-aware propagation model exists, remove this scan.
        if is_path_confined(source, &path, graph) {
            continue;
        }

        // ponytail: only flag when the taint flows through the FIRST argument
        // (file path). Taint in other arguments (file content, mode, flags) is
        // not path traversal. Upgrade: pre-compute this in the taint path query.
        if !is_first_arg_tainted(graph, &path) {
            continue;
        }

        let Some(TaintNode::Sink {
            function: sink_fn,
            byte_range: sink_range,
            ..
        }) = graph.nodes.get(path.sink_id)
        else {
            continue;
        };
        let (line, col) = unit.line_col(sink_range.start);
        let at = out.len();
        emit::push_finding_with_evidence(
            &META_CWE_22,
            file,
            line,
            col,
            "user-controlled input reaches a file-open sink without path sanitization",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo::new("FileOpen", sink_fn.to_string()),
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
        // Taint-core confidence higher than needle heuristics.
        for f in out.iter_mut().skip(at) {
            f.confidence = Some(0.75);
        }
    }
}

/// Check whether the taint flows through argument 0 (file path) of the sink.
fn is_first_arg_tainted(graph: &TaintGraph, path: &TaintPath) -> bool {
    for node_id in &path.node_ids {
        for edge in &graph.edges {
            if edge.from == *node_id
                && edge.to == path.sink_id
                && matches!(edge.kind, EdgeKind::Argument(0))
            {
                return true;
            }
        }
    }
    false
}

/// Confinement: `strings.HasPrefix` on a variable that appears on the taint
/// path (same binding). Does **not** treat `filepath.Clean` alone as safe.
/// Abs/EvalSymlinks are optional stronger evidence but Join+root+HasPrefix
/// is the common production pattern (and matches our safe fixtures).
fn is_path_confined(source: &str, path: &TaintPath, graph: &TaintGraph) -> bool {
    if !source.contains("strings.HasPrefix(") {
        return false;
    }
    for node_id in &path.node_ids {
        if let TaintNode::Variable { name, .. } = &graph.nodes[*node_id] {
            if scratch_contains(source, "strings.HasPrefix(", name.as_ref(), ",") {
                return true;
            }
        }
    }
    false
}
