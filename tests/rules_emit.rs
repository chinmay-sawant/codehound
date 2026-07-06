use codehound::rules::{
    DetectorEvidence, RuleMetadata, Severity, TaintSinkInfo, TaintSourceInfo, push_finding,
    push_finding_with_evidence, push_finding_with_snippet, rule_meta,
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
fn push_finding_variants_populate_correctly() {
    let meta = meta_with_cwe();

    // push_finding: basic fields
    let mut out1 = Vec::new();
    push_finding(&meta, "a.go", 12, 5, "msg", &mut out1);
    assert_eq!(out1.len(), 1);
    assert_eq!(out1[0].rule_id, "CWE-89");
    assert_eq!(out1[0].file, "a.go");
    assert_eq!(out1[0].line, 12);
    assert_eq!(out1[0].column, 5);
    assert_eq!(out1[0].message, "msg");
    assert_eq!(out1[0].severity, Severity::High);
    assert!(out1[0].snippet.is_none());
    assert!(out1[0].fix.is_none());
    assert!(out1[0].cwe.is_none());

    // push_finding_with_snippet
    let mut out2 = Vec::new();
    push_finding_with_snippet(&meta, "a.go", 1, 1, "msg", "select * from users", &mut out2);
    assert_eq!(out2[0].snippet.as_deref(), Some("select * from users"));
    assert!(out2[0].fix.is_none());

    // push_finding_with_evidence
    let mut out3 = Vec::new();
    push_finding_with_evidence(
        &meta,
        "a.go",
        1,
        1,
        "msg",
        DetectorEvidence::TaintFlow {
            source: TaintSourceInfo {
                kind: "UserInput".to_string(),
                function: "r.URL.Query".to_string(),
                variable: "host".to_string(),
            },
            sink: TaintSinkInfo::new("CommandExec", "exec.Command"),
            hops: 1,
            sanitized: false,
        },
        &mut out3,
    );
    assert!(matches!(
        out3[0].evidence,
        Some(DetectorEvidence::TaintFlow {
            ref sink,
            hops: 1,
            ..
        }) if sink.function == "exec.Command"
    ));

    // rule_meta const-evaluable
    let m = rule_meta("X", "t", "d", Severity::Info, &[], None);
    assert_eq!(m.id, "X");
    assert_eq!(m.severity, Severity::Info);
    assert!(m.cwe.is_empty());
    assert!(m.fix.is_none());
}
