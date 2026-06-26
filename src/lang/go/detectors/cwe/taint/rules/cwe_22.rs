//! Detect CWE-22 (Path Traversal) via taint flow.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_22;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};
use super::evidence::source_info;

pub fn detect_cwe_22_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

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
        let Some(TaintNode::Sink {
            function: sink_fn,
            byte_range: sink_range,
            ..
        }) = graph.nodes.get(path.sink_id)
        else {
            continue;
        };
        let (line, col) = unit.line_col(sink_range.start);
        emit::push_finding_with_evidence(
            &META_CWE_22,
            file,
            line,
            col,
            "user-controlled input reaches a file-open sink without path sanitization",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo {
                    kind: "FileOpen".to_string(),
                    function: sink_fn.to_string(),
                },
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
    }
}
