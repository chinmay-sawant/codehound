use std::borrow::Cow;

use slopguard::reporting::json::FindingJson;
use slopguard::rules::{DetectorEvidence, Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

#[derive(serde::Deserialize)]
struct LegacyFindingJson {
    rule_id: String,
    rule_title: String,
    category: String,
    file: String,
    line: usize,
    column: usize,
    fingerprint: String,
    message: String,
    severity: String,
    cwe: Vec<LegacyCweRef>,
    fix: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct LegacyCweRef {
    id: String,
    name: String,
    url: String,
}

#[test]
fn json_omits_structured_fields_when_unset() {
    let r = helpers::reporting::sample();
    let j = FindingJson::from(&r.findings[0]);
    let value = serde_json::to_value(&j).unwrap();

    assert!(value.get("evidence").is_none(), "{value}");
    assert!(value.get("confidence").is_none(), "{value}");
    assert!(value.get("tags").is_none(), "{value}");
    assert!(value.get("suppressed").is_none(), "{value}");
    assert!(value.get("remediation").is_none(), "{value}");
}

#[test]
fn json_emits_structured_fields_when_set() {
    let finding = Finding::new(FindingInputs::new(
        "CWE-78",
        "Command injection",
        "cmd.go",
        LineCol {
            line: 10,
            column: 3,
        },
        "command uses user input",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
    .with_evidence(DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(0),
    })
    .with_confidence(0.75)
    .with_tags(vec!["needs-review".to_string()])
    .with_remediation("Use an allowlisted command.");
    let value = serde_json::to_value(FindingJson::from(&finding)).unwrap();

    assert_eq!(value["evidence"]["kind"], "DangerousCall");
    assert_eq!(value["evidence"]["function"], "exec.Command");
    assert_eq!(value["confidence"], 0.75);
    assert_eq!(value["tags"][0], "needs-review");
    assert_eq!(value["remediation"], "Use an allowlisted command.");
}

#[test]
fn legacy_json_consumers_ignore_structured_fields() {
    let finding = Finding::new(FindingInputs::new(
        "CWE-78",
        "Command injection",
        "cmd.go",
        LineCol {
            line: 10,
            column: 3,
        },
        "command uses user input",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
    .with_evidence(DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(0),
    })
    .with_confidence(0.75)
    .with_tags(vec!["needs-review".to_string()])
    .with_remediation("Use an allowlisted command.");
    let json = serde_json::to_string(&FindingJson::from(&finding)).unwrap();

    let legacy: LegacyFindingJson = serde_json::from_str(&json).unwrap();

    assert_eq!(legacy.rule_id, "CWE-78");
    assert_eq!(legacy.rule_title, "Command injection");
    assert_eq!(legacy.category, "security");
    assert_eq!(legacy.file, "cmd.go");
    assert_eq!(legacy.line, 10);
    assert_eq!(legacy.column, 3);
    assert_eq!(legacy.fingerprint, "slopguard:1:CWE-78:cmd.go:10:3");
    assert_eq!(legacy.message, "command uses user input");
    assert_eq!(legacy.severity, "high");
    assert!(legacy.cwe.is_empty());
    assert_eq!(legacy.fix, None);
}

#[test]
fn json_finding_includes_bad_practice_category() {
    let finding = Finding::new(FindingInputs::new(
        "BP-1",
        "Discarded Error Return",
        "bad.go",
        LineCol { line: 3, column: 2 },
        "discarded error",
        Severity::Low,
        Cow::Borrowed(&[]),
    ));
    let value = serde_json::to_value(FindingJson::from(&finding)).unwrap();

    assert_eq!(value["category"], "bad_practice");
}
