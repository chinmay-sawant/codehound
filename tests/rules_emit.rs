use slopguard::rules::{
    RuleMetadata, Severity, push_finding, push_finding_with_snippet, rule_meta,
};

fn meta_with_cwe() -> RuleMetadata {
    rule_meta(
        "CWE-89",
        "SQL injection",
        "string-built SQL with user input",
        Severity::High,
        &[],
        None,
    )
}

#[test]
fn push_finding_populates_fields() {
    let mut out = Vec::new();
    push_finding(&meta_with_cwe(), "a.go", 12, 5, "msg", &mut out);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(f.rule_id, "CWE-89");
    assert_eq!(f.file, "a.go");
    assert_eq!(f.line, 12);
    assert_eq!(f.column, 5);
    assert_eq!(f.message, "msg");
    assert_eq!(f.severity, Severity::High);
    assert!(f.snippet.is_none());
    assert!(f.fix.is_none());
    assert!(f.cwe.is_none());
}

#[test]
fn push_finding_with_snippet_attaches_snippet_and_fix() {
    let mut out = Vec::new();
    push_finding_with_snippet(
        &meta_with_cwe(),
        "a.go",
        1,
        1,
        "msg",
        "select * from users",
        &mut out,
    );
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(f.snippet.as_deref(), Some("select * from users"));
    assert_eq!(f.fix.as_deref(), Some(""));
}

#[test]
fn rule_meta_const_evaluable() {
    let m = rule_meta("X", "t", "d", Severity::Info, &[], None);
    assert_eq!(m.id, "X");
    assert_eq!(m.severity, Severity::Info);
    assert!(m.cwe.is_empty());
    assert!(m.fix.is_none());
}
