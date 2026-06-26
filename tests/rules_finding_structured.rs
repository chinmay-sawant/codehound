use std::borrow::Cow;

use slopguard::rules::{DetectorEvidence, Finding, LineCol, Severity};

#[test]
fn fingerprint_is_stable_across_calls() {
    let f = Finding::new(
        "CWE-22",
        "title",
        "a.go",
        LineCol {
            line: 12,
            column: 5,
        },
        "msg",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    assert_eq!(f.fingerprint_string(), "slopguard:1:CWE-22:a.go:12:5");
    assert_eq!(f.fingerprint_string(), "slopguard:1:CWE-22:a.go:12:5");
}

#[test]
fn structured_output_builders_chain_and_serialize() {
    let f = Finding::new(
        "CWE-78",
        "Command injection",
        "cmd.go",
        LineCol {
            line: 12,
            column: 5,
        },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    )
    .with_evidence(DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(1),
    })
    .with_confidence(0.8)
    .with_tags(vec!["needs-review".to_string()])
    .with_remediation("Use a fixed executable and validate arguments.")
    .mark_suppressed();

    assert!(matches!(
        f.evidence,
        Some(DetectorEvidence::DangerousCall {
            ref function,
            argument_index: Some(1),
        }) if function == "exec.Command"
    ));
    assert_eq!(f.confidence, Some(0.8));
    assert_eq!(f.tags.as_deref(), Some(&["needs-review".to_string()][..]));
    assert!(f.suppressed);
    assert_eq!(
        f.remediation.as_deref(),
        Some("Use a fixed executable and validate arguments.")
    );

    let value: serde_json::Value = serde_json::to_value(&f).unwrap();
    assert_eq!(value["evidence"]["kind"], "DangerousCall");
    assert!((value["confidence"].as_f64().unwrap() - 0.8).abs() < 0.000_001);
    assert_eq!(value["tags"][0], "needs-review");
    assert_eq!(value["suppressed"], true);
    assert_eq!(
        value["remediation"],
        "Use a fixed executable and validate arguments."
    );
}
