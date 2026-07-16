#[cfg(test)]
mod t {
    use crate::core::ParsedUnit;
    use crate::lang::go::detectors::cwe::taint::extract::extract_taint_facts;

    use super::super::super::{
        build_taint_graph, compute_all_summaries, extract_call_graph, find_taint_paths,
        refine_summaries_multihop, refine_summaries_multihop_with_context,
    };
    use crate::lang::go::detectors::cwe::taint::{SanitizerKind, SinkKind, SourceKind};

    fn parse(source: &str) -> ParsedUnit {
        crate::lang::parser::parse_go(source).expect("valid Go")
    }

    #[test]
    fn finds_sql_injection_path() {
        let source = r#"package main
func lookup(db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    _ = db.Query(name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::SQLQuery,
            &[SanitizerKind::SQL],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }

    #[test]
    fn finds_path_traversal_path() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    _ = os.Open(path)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::FileOpen,
            &[SanitizerKind::Path],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }

    #[test]
    fn finds_command_injection_path() {
        let source = r#"package main
func run(r *http.Request) {
    name := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::CommandExec,
            &[SanitizerKind::Path],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }

    #[test]
    fn filepath_clean_is_not_classified_as_path_sanitizer() {
        use crate::lang::go::detectors::cwe::taint::extract::classify_sanitizer;
        // Clean alone is not path-traversal safe and must not suppress CWE-22/78.
        assert!(classify_sanitizer("filepath.Clean").is_none());
        assert!(classify_sanitizer("path.Clean").is_none());
        // Base still counts as Path (final component only).
        assert_eq!(
            classify_sanitizer("filepath.Base"),
            Some(SanitizerKind::Path)
        );
    }

    #[test]
    fn validation_sanitizer_flags_command_injection_path_as_sanitized() {
        let source = r#"package main
func run(r *http.Request) {
    raw := r.URL.Query().Get("cmd")
    name := sanitizeCmd(raw)
    exec.Command("sh", "-c", name)
}
func sanitizeCmd(s string) string { return s }
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::CommandExec,
            &[SanitizerKind::Validation],
        );
        assert_eq!(paths.len(), 1);
        assert!(paths[0].sanitized);
    }

    #[test]
    fn channel_send_is_unsupported_not_assignment() {
        let source = r#"package main
func f(r *http.Request, ch chan string) {
    x := r.URL.Query().Get("q")
    ch <- x
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert!(
            facts.unsupported_flows.iter().any(|u| matches!(
                u.kind,
                crate::lang::go::detectors::cwe::taint::UnsupportedFlowKind::Channel
            )),
            "expected channel unsupported flow, got {:?}",
            facts.unsupported_flows
        );
        assert!(
            !facts.assignments.iter().any(|a| a.is_channel_send),
            "channel sends must not be graph assignments"
        );
    }

    #[test]
    fn field_key_assignment_tracks_qualified_lhs() {
        let source = r#"package main
func f(r *http.Request) {
    var user struct{ Path string }
    user.Path = r.URL.Query().Get("p")
    _ = os.Open(user.Path)
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert!(
            facts
                .assignments
                .iter()
                .any(|a| a.lhs.as_ref() == "user.Path"),
            "expected field-qualified LHS, got {:?}",
            facts
                .assignments
                .iter()
                .map(|a| a.lhs.as_ref())
                .collect::<Vec<_>>()
        );
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::FileOpen,
            &[SanitizerKind::Path],
        );
        assert!(
            !paths.is_empty(),
            "field-qualified path should reach FileOpen sink"
        );
    }

    #[test]
    fn versioned_last_write_prefers_assignment_before_use() {
        // Second assignment overwrites taint with constant; sink should not fire.
        let source = r#"package main
func f(r *http.Request) {
    name := r.URL.Query().Get("name")
    name = "safe"
    _ = db.Query(name)
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::SQLQuery,
            &[SanitizerKind::SQL],
        );
        // Last write is constant — no unsanitized path from source to sink.
        assert!(
            paths.is_empty() || paths.iter().all(|p| p.sanitized),
            "expected no live taint after overwrite, got {paths:?}"
        );
    }

    #[test]
    fn unsanitized_branch_is_not_hidden_by_sanitized_merge() {
        use std::ops::Range;
        use std::sync::Arc;

        use crate::lang::go::detectors::cwe::taint::{EdgeKind, TaintGraph, TaintNode};

        let mut graph = TaintGraph::default();
        let source = graph.add_node(TaintNode::Source {
            function: Arc::from("source"),
            kind: SourceKind::UserInput,
            byte_range: Range { start: 0, end: 1 },
        });
        let sanitizer = graph.add_node(TaintNode::Sanitizer {
            function: Arc::from("sanitize"),
            kind: SanitizerKind::Validation,
            byte_range: 1..2,
        });
        let merge = graph.add_node(TaintNode::Variable {
            name: Arc::from("merged"),
            type_hint: None,
            scope: 0,
            decl_byte: 2,
        });
        let sink = graph.add_node(TaintNode::Sink {
            function: Arc::from("sink"),
            kind: SinkKind::CommandExec,
            argument_index: 0,
            byte_range: 3..4,
        });
        graph.add_edge(source, sanitizer, EdgeKind::PassThrough);
        graph.add_edge(sanitizer, merge, EdgeKind::PassThrough);
        graph.add_edge(source, merge, EdgeKind::PassThrough);
        graph.add_edge(merge, sink, EdgeKind::Argument(0));

        assert!(super::super::unsanitized_reaches_any(
            &graph,
            source,
            &[sink]
        ));
    }

    #[test]
    fn direct_sink_summary_is_function_local() {
        let source = r#"package main
func source_only(r *http.Request) {
    _ = r.URL.Query().Get("q")
}
func sink_only() {
    _ = os.Open("/safe")
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let summaries = compute_all_summaries(&facts, source);

        assert!(!summaries["source_only"].has_direct_sink);
        assert!(!summaries["sink_only"].has_direct_sink);
    }

    #[test]
    fn return_refinement_requires_returning_the_callee_result() {
        let source = r#"package main
func source() string {
    return r.URL.Query().Get("q")
}
func unused() string {
    x := source()
    _ = x
    return "/safe"
}
func used() string {
    x := source()
    return x
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let mut summaries = compute_all_summaries(&facts, source);
        refine_summaries_multihop(&extract_call_graph(&unit), &mut summaries, 4);

        assert!(
            !summaries["unused"]
                .return_sources
                .iter()
                .any(|tainted| *tainted)
        );
        assert!(
            summaries["used"]
                .return_sources
                .iter()
                .any(|tainted| *tainted)
        );
    }

    #[test]
    fn parameter_refinement_follows_direct_argument_bindings() {
        let source = r#"package main
func middle(s string) {
    leaf(s)
}
func leaf(s string) {
    os.Open(s)
}
"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let mut summaries = compute_all_summaries(&facts, source);
        refine_summaries_multihop_with_context(
            &extract_call_graph(&unit),
            &facts,
            &mut summaries,
            4,
        );

        assert_eq!(summaries["middle"].param_sources, vec![Some(true)]);
    }
}
