use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_91;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo, TaintSourceInfo};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};
use super::evidence::variable_name_at;

pub fn detect_cwe_91_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::XMLQuery,
        &[SanitizerKind::XML],
    );

    for path in paths {
        if path.sanitized {
            continue;
        }
        let Some(TaintNode::Source {
            function: source_fn,
            ..
        }) = graph.nodes.get(path.source_id)
        else {
            continue;
        };
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
            &META_CWE_91,
            file,
            line,
            col,
            "user-controlled input reaches an XML unmarshalling sink without escaping",
            DetectorEvidence::TaintFlow {
                source: TaintSourceInfo {
                    kind: "UserInput".to_string(),
                    function: source_fn.to_string(),
                    variable: variable_name_at(graph, path.source_id).unwrap_or_default(),
                },
                sink: TaintSinkInfo::new("XMLQuery", sink_fn.to_string()),
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
    }
}
