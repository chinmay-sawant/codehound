//! Taint-based detectors for the four rewritten CWE rules.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::{
    META_CWE_22, META_CWE_78, META_CWE_79, META_CWE_89,
};
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo, TaintSourceInfo};

use super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};

/// Detect CWE-78 (OS Command Injection) via taint flow.
pub fn detect_cwe_78_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

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

/// Detect CWE-89 (SQL Injection) via taint flow.
pub fn detect_cwe_89_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::SQLQuery,
        &[SanitizerKind::SQL],
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
            &META_CWE_89,
            file,
            line,
            col,
            "user-controlled input reaches an SQL execution sink",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo {
                    kind: "SQLQuery".to_string(),
                    function: sink_fn.to_string(),
                },
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
    }
}

/// Detect CWE-22 (Path Traversal) via taint flow.
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

/// Detect CWE-79 (XSS) via taint flow.
pub fn detect_cwe_79_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::Template,
        &[SanitizerKind::HTML],
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
            &META_CWE_79,
            file,
            line,
            col,
            "user-controlled input reaches a template execution sink without HTML escaping",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo {
                    kind: "Template".to_string(),
                    function: sink_fn.to_string(),
                },
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
    }
}

fn variable_name_at(graph: &super::TaintGraph, node_id: usize) -> Option<String> {
    match graph.nodes.get(node_id)? {
        TaintNode::Variable { name, .. } => Some(name.to_string()),
        TaintNode::Source { .. } => {
            // Find an outgoing assignment edge to a variable.
            graph
                .edges
                .iter()
                .find(|e| e.from == node_id && matches!(e.kind, super::EdgeKind::Assignment))
                .and_then(|e| variable_name_at(graph, e.to))
        }
        _ => None,
    }
}

fn source_info(graph: &super::TaintGraph, path: &super::TaintPath) -> TaintSourceInfo {
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
