use slopguard::engine::ScanError;
use slopguard::engine::ScanErrorKind;
use slopguard::reporting::json::Envelope;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn envelope_includes_tool_name() {
    let r = helpers::reporting::sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"tool\": \"slopguard\""), "got: {s}");
}

#[test]
fn envelope_includes_version_field() {
    let r = helpers::reporting::sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"version\""), "got: {s}");
}

#[test]
fn envelope_reports_finding_count() {
    let r = helpers::reporting::sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"findingCount\": 1"), "got: {s}");
}

#[test]
fn envelope_reports_zero_errors_by_default() {
    let r = helpers::reporting::sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(s.contains("\"errorCount\": 0"), "got: {s}");
}

#[test]
fn envelope_serializes_finding_fingerprint() {
    let r = helpers::reporting::sample();
    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();
    assert!(
        s.contains("\"fingerprint\": \"slopguard:1:CWE-89:a.go:12:5\""),
        "got: {s}"
    );
}

#[test]
fn envelope_with_errors_includes_error_count() {
    let r = {
        let mut r = helpers::reporting::sample();
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
    let mut r = helpers::reporting::sample();
    r.suppressed_count = 3;

    let env = Envelope::from(&r);
    let s = serde_json::to_string_pretty(&env).unwrap();

    assert!(s.contains("\"suppressedCount\": 3"), "got: {s}");
}
