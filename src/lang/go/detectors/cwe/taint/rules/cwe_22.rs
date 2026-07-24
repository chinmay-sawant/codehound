//! Detect CWE-22 (Path Traversal) via taint flow.

use crate::core::ParsedUnit;
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

#[cfg(test)]
mod tests {
    use crate::lang::go::detectors::cwe::facts::{
        FactBuildOpts, build_go_unit_facts_with, build_taint_graph_for_facts,
    };
    use crate::lang::go::detectors::cwe::taint::extract::classify_sanitizer;

    use super::*;

    fn cwe_22_findings(source: &str) -> usize {
        let unit = crate::lang::parser::parse_go(source).expect("valid Go");
        let mut facts = build_go_unit_facts_with(&unit, FactBuildOpts::TAINT);
        build_taint_graph_for_facts(&mut facts);
        let mut findings = Vec::new();
        detect_cwe_22_taint(&unit, &facts, &mut findings);
        findings.len()
    }

    #[test]
    fn unescape_string_is_not_an_html_sanitizer() {
        assert!(classify_sanitizer("html.UnescapeString").is_none());
    }

    #[test]
    fn post_closure_tainted_sink_still_fires() {
        let source = r#"package main
func serve(r *http.Request) {
    _ = func() { local := "inner"; _ = local }
    path := r.URL.Query().Get("path")
    os.Open(path)
}"#;
        assert_eq!(cwe_22_findings(source), 1);
    }

    #[test]
    fn unrelated_prefix_check_does_not_suppress_path_taint() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    other := "/safe"
    if !strings.HasPrefix(other, "/safe") { return }
    os.Open(path)
}"#;
        assert_eq!(cwe_22_findings(source), 1);
    }

    #[test]
    fn prefix_guard_does_not_prove_path_confinement() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    if !strings.HasPrefix(path, "/safe/") { return }
    os.Open(path)
}"#;
        assert_eq!(cwe_22_findings(source), 1);
    }
}
