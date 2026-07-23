//! Detect CWE-79 (XSS) via taint flow.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_79;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo};

use super::super::{SanitizerKind, SinkKind, SourceKind, TaintNode, find_taint_paths};
use super::evidence::source_info;

pub fn detect_cwe_79_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

    // Template sinks (html/template.Execute*) and HTTP write sinks (w.Write,
    // fmt.Fprintf). Not full XSS coverage — no DOM, no framework auto-escape model.
    for (sink_kind, sink_label, message) in [
        (
            SinkKind::Template,
            "Template",
            "user-controlled input reaches a template execution sink without HTML escaping",
        ),
        (
            SinkKind::HTTPWrite,
            "HTTPWrite",
            "user-controlled input reaches an HTTP write sink without HTML escaping",
        ),
    ] {
        let paths = find_taint_paths(
            graph,
            SourceKind::UserInput,
            sink_kind,
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
                message,
                DetectorEvidence::TaintFlow {
                    source: source_info(graph, &path),
                    sink: TaintSinkInfo::new(sink_label, sink_fn.to_string()),
                    hops: path.node_ids.len().saturating_sub(1),
                    sanitized: false,
                },
                out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lang::go::detectors::cwe::facts::{
        FactBuildOpts, build_go_unit_facts_with, build_taint_graph_for_facts,
    };

    use super::*;

    fn cwe_79_findings(source: &str) -> usize {
        let unit = crate::lang::parser::parse_go(source).expect("valid Go");
        let mut facts = build_go_unit_facts_with(&unit, FactBuildOpts::TAINT);
        build_taint_graph_for_facts(&mut facts);
        let mut findings = Vec::new();
        detect_cwe_79_taint(&unit, &facts, &mut findings);
        findings.len()
    }

    #[test]
    fn html_template_escapes_plain_unescaped_strings() {
        let source = r#"package main
import (
    "html"
    "html/template"
    "net/http"
)
func RenderPage(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    raw := html.UnescapeString(name)
    t := template.Must(template.New("x").Parse("<html>{{.}}</html>"))
    _ = t.Execute(w, raw)
}"#;
        assert_eq!(cwe_79_findings(source), 0);
    }

    #[test]
    fn text_template_unescape_string_remains_an_xss_flow() {
        let source = r#"package main
import (
    "html"
    "net/http"
    "text/template"
)
func RenderPage(w http.ResponseWriter, r *http.Request) {
    raw := html.UnescapeString(r.URL.Query().Get("name"))
    t := template.Must(template.New("x").Parse("<html>{{.}}</html>"))
    _ = t.Execute(w, raw)
}"#;
        assert_eq!(cwe_79_findings(source), 1);
    }

    #[test]
    fn html_template_trusted_content_conversion_remains_an_xss_flow() {
        let source = r#"package main
import (
    "html"
    "html/template"
    "net/http"
)
func RenderPage(w http.ResponseWriter, r *http.Request) {
    raw := html.UnescapeString(r.URL.Query().Get("name"))
    t := template.Must(template.New("x").Parse("<html>{{.}}</html>"))
    _ = t.Execute(w, template.HTML(raw))
}"#;
        assert_eq!(cwe_79_findings(source), 1);
    }

    #[test]
    fn aliased_html_template_trusted_content_conversion_remains_an_xss_flow() {
        let source = r#"package main
import (
    tmpl "html/template"
    "net/http"
)
func RenderPage(w http.ResponseWriter, r *http.Request) {
    raw := r.URL.Query().Get("name")
    body := tmpl.HTML(raw)
    t := tmpl.Must(tmpl.New("x").Parse("<html>{{.}}</html>"))
    _ = t.Execute(w, body)
}"#;
        assert_eq!(cwe_79_findings(source), 1);
    }

    #[test]
    fn fmt_fprintf_to_a_buffer_named_w_is_not_an_http_xss_sink() {
        let source = r#"package main
import (
    "bytes"
    "fmt"
    "net/http"
)
func RenderPage(r *http.Request) {
    name := r.URL.Query().Get("name")
    var w bytes.Buffer
    _, _ = fmt.Fprintf(&w, "%s", name)
}"#;
        assert_eq!(cwe_79_findings(source), 0);
    }

    #[test]
    fn fmt_fprintf_to_a_declared_response_writer_remains_an_xss_sink() {
        let source = r#"package main
import (
    "fmt"
    "net/http"
)
func RenderPage(response http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    _, _ = fmt.Fprintf(response, "%s", name)
}"#;
        assert_eq!(cwe_79_findings(source), 1);
    }
}
