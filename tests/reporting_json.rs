use std::borrow::Cow;

use slopguard::cwe::CweRef;
use slopguard::engine::{AnalysisResult, ScanError, ScanErrorKind};
use slopguard::reporting::json::{Envelope, FindingJson};
use slopguard::rules::{Finding, LineCol, Severity};

fn sample() -> AnalysisResult {
    AnalysisResult {
        findings: vec![Finding::new(
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
        )],
        errors: vec![],
    }
}

fn sample_with_cwe() -> AnalysisResult {
    let cwes: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
        89,
        "SQL Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    )]));
    AnalysisResult {
        findings: vec![Finding::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(cwes),
        )],
        errors: vec![],
    }
}

#[test]
fn envelope_has_tool_version_and_finding_count() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"tool\": \"slopguard\""), "got: {s}");
    assert!(s.contains("\"version\""), "got: {s}");
    assert!(s.contains("\"findingCount\": 1"), "got: {s}");
    assert!(s.contains("\"errorCount\": 0"), "got: {s}");
}

#[test]
fn envelope_serializes_finding_fingerprint() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(
        s.contains("\"fingerprint\": \"CWE-89:a.go:12:5\""),
        "got: {s}"
    );
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
        findings: vec![
            Finding::new(
                "CWE-1",
                "a",
                "a.go",
                LineCol { line: 1, column: 1 },
                "m1",
                Severity::Info,
                Cow::Borrowed(&[]),
            ),
            Finding::new(
                "CWE-2",
                "b",
                "b.go",
                LineCol { line: 2, column: 2 },
                "m2",
                Severity::Info,
                Cow::Borrowed(&[]),
            ),
        ],
        errors: vec![],
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
        lines[1].contains("\"rule_id\":\"CWE-2\""),
        "got: {}",
        lines[1]
    );
}

#[test]
fn envelope_with_errors_includes_error_count() {
    let r = {
        let mut r = sample();
        r.errors = vec![ScanError {
            path: std::path::PathBuf::from("x.go"),
            kind: ScanErrorKind::Io,
            message: "permission denied".to_string(),
        }];
        r
    };
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"errorCount\": 1"), "got: {s}");
}
