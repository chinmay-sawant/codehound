#[cfg(test)]
mod t {
    use crate::core::ParsedUnit;
    use crate::lang::go::detectors::cwe::taint::extract_taint_facts;
    use crate::lang::go::detectors::cwe::taint::{ScopeKind, SinkKind, SourceKind};

    fn parse(source: &str) -> ParsedUnit {
        crate::lang::go::parser::parse_go(source).expect("valid Go")
    }

    #[test]
    fn extracts_user_input_source() {
        let source = r#"package main
func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("x")
    _ = q
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert_eq!(facts.sources.len(), 1);
        assert_eq!(facts.sources[0].kind, SourceKind::UserInput);
        assert!(facts.sources[0].function.as_ref().contains("Query"));
    }

    #[test]
    fn extracts_command_sink() {
        let source = r#"package main
func run(name string) {
    exec.Command("sh", "-c", name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert_eq!(facts.sinks.len(), 1);
        assert_eq!(facts.sinks[0].kind, SinkKind::CommandExec);
    }

    #[test]
    fn extracts_scopes() {
        let source = r#"package main
func f() {
    if true {
        x := 1
        _ = x
    }
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert!(facts.scopes.iter().any(|s| s.kind == ScopeKind::Function));
        assert!(facts.scopes.iter().any(|s| s.kind == ScopeKind::If));
    }

    #[test]
    fn taint_extraction_overhead_is_small() {
        use std::time::Instant;

        let mut lines = String::from("package main\n");
        for i in 0..500 {
            lines.push_str(&format!(
                "func f{i}(w http.ResponseWriter, r *http.Request) {{
    q := r.URL.Query().Get(\"x\")
    cmd := exec.Command(\"sh\", \"-c\", q)
    _ = cmd
}}\n"
            ));
        }
        let unit = parse(&lines);

        let start = Instant::now();
        let facts = extract_taint_facts(&unit);
        let elapsed = start.elapsed();

        assert_eq!(facts.sources.len(), 500);
        assert_eq!(facts.sinks.len(), 500);
        assert!(
            elapsed.as_millis() < 50,
            "taint extraction on 500-function file took {elapsed:?}, budget 50ms"
        );
    }
}
