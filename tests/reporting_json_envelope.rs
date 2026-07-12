use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::engine::ScanError;
use codehound::engine::ScanErrorKind;
use codehound::reporting::json::Envelope;
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

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

#[test]
fn envelope_includes_tool_name() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"tool\": \"codehound\""), "got: {s}");
}

#[test]
fn envelope_includes_version_field() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"version\""), "got: {s}");
}

#[test]
fn envelope_reports_finding_count() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"findingCount\": 1"), "got: {s}");
}

#[test]
fn envelope_reports_zero_errors_by_default() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"errorCount\": 0"), "got: {s}");
}

#[test]
fn envelope_serializes_finding_fingerprint() {
    let r = sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(
        s.contains("\"fingerprint\": \"codehound:2:CWE-89:a.go:"),
        "expected v2 fingerprint prefix, got: {s}"
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

#[test]
fn envelope_includes_suppressed_count() {
    let mut r = sample();
    r.suppressed_count = 3;

    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();

    assert!(s.contains("\"suppressedCount\": 3"), "got: {s}");
}

#[test]
fn envelope_snapshot_is_stable() {
    use insta::assert_snapshot;

    let sample = sample();
    let env = Envelope::from(&sample);
    let mut s = serde_json::to_string_pretty(&env).unwrap();
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&s) {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("version");
        }
        s = serde_json::to_string_pretty(&v).unwrap();
    }
    assert_snapshot!("json_envelope", s);
}
