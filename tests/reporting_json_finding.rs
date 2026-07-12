use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::reporting::json::{Envelope, FindingJson};
use codehound::rules::{
    DetectorEvidence, Finding, FindingInputs, LineCol, Severity, TaintHop, TaintSinkInfo,
    TaintSourceInfo,
};

#[path = "helpers/mod.rs"]
mod helpers;

fn sample() -> AnalysisResult {
    helpers::reporting::sample_result(vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "SQL injection",
        "a.go",
        LineCol {
            line: 12,
            column: 5,
        },
        "user input is concatenated into the query",
        Severity::High,
        Cow::Borrowed(&[]),
    ))])
}

fn sample_with_cwe() -> AnalysisResult {
    let cwes: &'static [codehound::cwe::CweRef] =
        Box::leak(Box::new([codehound::cwe::CweRef::new(
            89,
            "SQL Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        )]));
    helpers::reporting::sample_result(vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "SQL injection",
        "a.go",
        LineCol { line: 1, column: 1 },
        "msg",
        Severity::High,
        Cow::Borrowed(cwes),
    ))])
}

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
    let r = sample();
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
    .with_evidence(DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".into(),
            function: "r.URL.Query".into(),
            variable: "host".into(),
        },
        sink: TaintSinkInfo::new("CommandExec", "exec.Command"),
        hops: 1,
        sanitized: false,
    })
    .with_confidence(0.75)
    .with_tags(vec!["needs-review".to_string()])
    .with_remediation("Use an allowlisted command.");
    let value = serde_json::to_value(FindingJson::from(&finding)).unwrap();

    assert_eq!(value["evidence"]["kind"], "TaintFlow");
    assert_eq!(value["evidence"]["sink"]["function"], "exec.Command");
    assert_eq!(value["confidence"], 0.75);
    assert_eq!(value["tags"][0], "needs-review");
    assert_eq!(value["remediation"], "Use an allowlisted command.");
}

#[test]
fn json_marks_taint_show_paths_when_taint_hops_are_present() {
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
    .with_evidence(DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".into(),
            function: "r.URL.Query".into(),
            variable: "host".into(),
        },
        sink: TaintSinkInfo {
            kind: "CommandExec".into(),
            function: "exec.Command".into(),
            hop_details: vec![TaintHop {
                function: "exec.Command".into(),
                kind: "CommandExec".into(),
                variable: "host".into(),
                file: "cmd.go".into(),
                line: 10,
            }],
        },
        hops: 1,
        sanitized: false,
    });
    let value = serde_json::to_value(FindingJson::from(&finding)).unwrap();

    assert_eq!(value["taint_show_paths"], true);
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
    .with_evidence(DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".into(),
            function: "r.URL.Query".into(),
            variable: "host".into(),
        },
        sink: TaintSinkInfo::new("CommandExec", "exec.Command"),
        hops: 1,
        sanitized: false,
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
    assert!(
        legacy.fingerprint.starts_with("codehound:2:CWE-78:cmd.go:"),
        "got: {}",
        legacy.fingerprint
    );
    assert_eq!(legacy.message, "command uses user input");
    assert_eq!(legacy.severity, "high");
    assert!(legacy.cwe.is_empty());
    assert_eq!(legacy.fix, None);
}

#[test]
fn cwe_id_serialized_as_cwe_n_string() {
    let r = sample_with_cwe();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"id\": \"CWE-89\""), "got: {s}");
}

#[test]
fn ndjson_emits_one_finding_per_line() {
    let result = AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![
            Finding::new(FindingInputs::new(
                "CWE-1",
                "a",
                "a.go",
                LineCol { line: 1, column: 1 },
                "m1",
                Severity::Info,
                Cow::Borrowed(&[]),
            )),
            Finding::new(FindingInputs::new(
                "CWE-2",
                "b",
                "b.go",
                LineCol { line: 2, column: 2 },
                "m2",
                Severity::Info,
                Cow::Borrowed(&[]),
            )),
        ],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    };
    let mut buf = Vec::new();
    for f in &result.findings {
        serde_json::to_writer(&mut buf, &FindingJson::from(f)).unwrap();
        buf.push(b'\n');
    }
    let s = std::str::from_utf8(&buf).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 NDJSON lines, got: {s}");
    assert!(
        lines[0].contains("\"rule_id\":\"CWE-1\""),
        "got: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("\"fingerprint\":\"codehound:2:CWE-1:a.go:"),
        "got: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"rule_id\":\"CWE-2\""),
        "got: {}",
        lines[1]
    );
}
