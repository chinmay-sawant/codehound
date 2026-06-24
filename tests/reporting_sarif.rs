use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::reporting::sarif::render_to_string;
use slopguard::rules::{DetectorEvidence, Finding, LineCol, Severity};

fn sample_result() -> AnalysisResult {
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![
            Finding::new(
                "CWE-22",
                "Path traversal",
                "a.go",
                LineCol { line: 1, column: 1 },
                "msg",
                Severity::High,
                Cow::Borrowed(&[]),
            ),
            Finding::new(
                "CWE-89",
                "SQL injection",
                "b.go",
                LineCol { line: 2, column: 3 },
                "msg2",
                Severity::Critical,
                Cow::Borrowed(&[]),
            ),
        ],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    }
}

fn iso8601_from_secs(secs: u64) -> String {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[test]
fn driver_fields_are_populated() {
    let log = render_to_string(&sample_result());
    assert!(log.contains("\"informationUri\""), "got: {log}");
    assert!(log.contains("\"semanticVersion\""), "got: {log}");
    assert!(log.contains("\"name\": \"slopguard\""), "got: {log}");
}

#[test]
fn rules_array_is_sorted_alphabetically() {
    let log = render_to_string(&sample_result());
    let i22 = log.find("\"CWE-22\"").expect("CWE-22");
    let i89 = log.find("\"CWE-89\"").expect("CWE-89");
    assert!(i22 < i89, "CWE-22 should appear before CWE-89, got: {log}");
}

#[test]
fn results_have_rule_index_pointing_into_rules() {
    let log = render_to_string(&sample_result());
    assert!(log.contains("\"ruleIndex\""), "got: {log}");
}

#[test]
fn results_have_partial_fingerprints() {
    let log = render_to_string(&sample_result());
    assert!(
        log.contains("\"partialFingerprints\""),
        "missing partialFingerprints, got: {log}"
    );
    assert!(
        log.contains("\"slopguard/v1\": \"slopguard:1:CWE-22:a.go:1:1\""),
        "missing canonical fingerprint, got: {log}"
    );
}

#[test]
fn results_have_security_severity_in_properties() {
    let log = render_to_string(&sample_result());
    assert!(log.contains("\"security-severity\""), "got: {log}");
    assert!(log.contains("\"tags\""), "got: {log}");
}

#[test]
fn invocations_block_present() {
    let log = render_to_string(&sample_result());
    assert!(log.contains("\"invocations\""), "got: {log}");
    assert!(log.contains("\"endTimeUtc\""), "got: {log}");
}

#[test]
fn invocation_includes_suppressed_count_when_present() {
    let mut result = sample_result();
    result.suppressed_count = 2;

    let log = render_to_string(&result);

    assert!(log.contains("\"suppressedFindings\": 2"), "got: {log}");
}

#[test]
fn end_line_end_column_byte_offset_optional() {
    let mut r = sample_result();
    r.findings[0].end_line = Some(2);
    r.findings[0].end_column = Some(8);
    r.findings[0].byte_offset = Some(42);
    r.findings[0].byte_length = Some(7);
    let log = render_to_string(&r);
    assert!(log.contains("\"endLine\": 2"), "got: {log}");
    assert!(log.contains("\"endColumn\": 8"), "got: {log}");
    assert!(log.contains("\"byteOffset\": 42"), "got: {log}");
    assert!(log.contains("\"byteLength\": 7"), "got: {log}");
}

#[test]
fn region_end_fields_absent_when_unset() {
    let r = sample_result();
    let log = render_to_string(&r);
    assert!(!log.contains("endLine"), "got: {log}");
    assert!(!log.contains("byteOffset"), "got: {log}");
}

#[test]
fn iso8601_format_is_correct() {
    let s = iso8601_from_secs(1_704_067_200);
    assert_eq!(s, "2024-01-01T00:00:00Z");
}

#[test]
fn rank_is_absent_when_confidence_unset() {
    let log = render_to_string(&sample_result());
    assert!(!log.contains("\"rank\""), "got: {log}");
}

#[test]
fn rank_maps_confidence_to_sarif_scale() {
    let mut r = sample_result();
    r.findings[0].confidence = Some(0.75);

    let log = render_to_string(&r);
    assert!(log.contains("\"rank\": 75"), "got: {log}");
}

#[test]
fn suppressions_are_absent_when_not_suppressed() {
    let log = render_to_string(&sample_result());
    assert!(!log.contains("\"suppressions\""), "got: {log}");
}

#[test]
fn suppressions_present_when_finding_suppressed() {
    let mut r = sample_result();
    r.findings[0].suppressed = true;

    let log = render_to_string(&r);
    assert!(log.contains("\"suppressions\""), "got: {log}");
    assert!(log.contains("\"kind\": \"external\""), "got: {log}");
}

#[test]
fn evidence_maps_to_slopguard_evidence_property() {
    let mut r = sample_result();
    r.findings[0].evidence = Some(DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(2),
    });

    let log = render_to_string(&r);
    assert!(log.contains("\"slopguardEvidence\""), "got: {log}");
    assert!(log.contains("\"kind\": \"DangerousCall\""), "got: {log}");
    assert!(log.contains("\"function\": \"exec.Command\""), "got: {log}");
}

#[test]
fn remediation_maps_to_properties_remediation() {
    let mut r = sample_result();
    r.findings[0].remediation = Some("Use parameterized queries.".to_string());

    let log = render_to_string(&r);
    assert!(
        log.contains("\"remediation\": \"Use parameterized queries.\""),
        "got: {log}"
    );
}

#[test]
fn finding_tags_are_included_in_properties_tags() {
    let mut r = sample_result();
    r.findings[0].tags = Some(vec![
        "needs-review".to_string(),
        "false-positive-risk".to_string(),
    ]);

    let log = render_to_string(&r);
    let tags_start = log.find("\"tags\"").expect("tags property");
    let tags_section = &log[tags_start..tags_start + 200];
    assert!(tags_section.contains("\"needs-review\""), "got: {log}");
    assert!(
        tags_section.contains("\"false-positive-risk\""),
        "got: {log}"
    );
}
