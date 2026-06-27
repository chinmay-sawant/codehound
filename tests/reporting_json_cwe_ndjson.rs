use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::reporting::json::{Envelope, FindingJson};
use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn cwe_id_serialized_as_cwe_n_string() {
    let r = helpers::reporting::sample_with_cwe();
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
        lines[0].contains("\"fingerprint\":\"slopguard:1:CWE-1:a.go:1:1\""),
        "got: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"rule_id\":\"CWE-2\""),
        "got: {}",
        lines[1]
    );
}
