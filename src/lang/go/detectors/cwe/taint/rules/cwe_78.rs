//! Detect CWE-78 (OS Command Injection) via taint flow.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_78;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo, TaintSourceInfo};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};
use super::evidence::variable_name_at;

pub fn detect_cwe_78_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::CommandExec,
        &[SanitizerKind::Path],
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

        // ponytail: exec.Command with direct argv (no shell) can't inject shell
        // commands — only flag when first two args are "sh"/"bash" and "-c".
        if sink_fn.as_ref() == "exec.Command" && !has_shell_args(source, sink_range) {
            continue;
        }

        let (line, col) = unit.line_col(sink_range.start);
        emit::push_finding_with_evidence(
            &META_CWE_78,
            file,
            line,
            col,
            "user-controlled input reaches a shell command execution sink",
            DetectorEvidence::TaintFlow {
                source: TaintSourceInfo {
                    kind: "UserInput".to_string(),
                    function: source_fn.to_string(),
                    variable: variable_name_at(graph, path.source_id).unwrap_or_default(),
                },
                sink: TaintSinkInfo {
                    kind: "CommandExec".to_string(),
                    function: sink_fn.to_string(),
                },
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
    }
}

/// Check if the exec.Command call includes a shell ("sh", "-c" or "bash", "-c").
fn has_shell_args(source: &str, range: &std::ops::Range<usize>) -> bool {
    let call = &source[range.start..range.end];
    let stripped: String = call.chars().filter(|c| !c.is_whitespace()).collect();
    stripped.contains(r#""sh","-c","#) || stripped.contains(r#""bash","-c","#)
}
