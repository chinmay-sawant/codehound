#[cfg(test)]
mod t {
    use crate::core::ParsedUnit;
    use crate::lang::go::detectors::cwe::taint::extract::extract_taint_facts;

    use super::super::super::{build_taint_graph, find_taint_paths};
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
            facts
                .unsupported_flows
                .iter()
                .any(|u| matches!(u.kind, crate::lang::go::detectors::cwe::taint::UnsupportedFlowKind::Channel)),
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
            facts.assignments.iter().any(|a| a.lhs.as_ref() == "user.Path"),
            "expected field-qualified LHS, got {:?}",
            facts.assignments.iter().map(|a| a.lhs.as_ref()).collect::<Vec<_>>()
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
}
