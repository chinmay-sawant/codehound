use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::reporting::sarif::render_to_string;
use codehound::rules::{
    DetectorEvidence, Finding, FindingInputs, LineCol, Severity, TaintHop, TaintSinkInfo,
    TaintSourceInfo,
};

#[path = "helpers/mod.rs"]
mod helpers;

fn sample_result() -> AnalysisResult {
    helpers::reporting::sample_result(vec![
        Finding::new(FindingInputs::new(
            "CWE-22",
            "Path traversal",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        )),
        Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "b.go",
            LineCol { line: 2, column: 3 },
            "msg2",
            Severity::Critical,
            Cow::Borrowed(&[]),
        )),
    ])
}

#[test]
fn driver_fields_are_populated() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(log.contains("\"informationUri\""), "got: {log}");
    assert!(log.contains("\"semanticVersion\""), "got: {log}");
    assert!(log.contains("\"name\": \"codehound\""), "got: {log}");
}

#[test]
fn rules_array_is_sorted_alphabetically() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    let i22 = log.find("\"CWE-22\"").expect("CWE-22");
    let i89 = log.find("\"CWE-89\"").expect("CWE-89");
    assert!(i22 < i89, "CWE-22 should appear before CWE-89, got: {log}");
}

#[test]
fn results_have_rule_index_pointing_into_rules() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(log.contains("\"ruleIndex\""), "got: {log}");
}

#[test]
fn results_have_partial_fingerprints() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(
        log.contains("\"partialFingerprints\""),
        "missing partialFingerprints, got: {log}"
    );
    assert!(
        log.contains("\"codehound/v1\": \"codehound:1:CWE-22:a.go:1:1\""),
        "missing canonical fingerprint, got: {log}"
    );
}

#[test]
fn results_have_security_severity_in_properties() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(log.contains("\"security-severity\""), "got: {log}");
    assert!(log.contains("\"tags\""), "got: {log}");
}

#[test]
fn iso8601_format_is_correct() {
    let ts = jiff::Timestamp::from_second(1_704_067_200).unwrap();
    let s = ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    assert_eq!(s, "2024-01-01T00:00:00Z");
}

#[test]
fn end_line_end_column_byte_offset_optional() {
    let mut r = sample_result();
    r.findings[0].end_line = Some(2);
    r.findings[0].end_column = Some(8);
    r.findings[0].byte_offset = Some(42);
    r.findings[0].byte_length = Some(7);
    let log = render_to_string(&r).expect("render SARIF");
    assert!(log.contains("\"endLine\": 2"), "got: {log}");
    assert!(log.contains("\"endColumn\": 8"), "got: {log}");
    assert!(log.contains("\"byteOffset\": 42"), "got: {log}");
    assert!(log.contains("\"byteLength\": 7"), "got: {log}");
}

#[test]
fn region_end_fields_absent_when_unset() {
    let r = sample_result();
    let log = render_to_string(&r).expect("render SARIF");
    assert!(!log.contains("endLine"), "got: {log}");
    assert!(!log.contains("byteOffset"), "got: {log}");
}

#[test]
fn rank_is_absent_when_confidence_unset() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(!log.contains("\"rank\""), "got: {log}");
}

#[test]
fn rank_maps_confidence_to_sarif_scale() {
    let mut r = sample_result();
    r.findings[0].confidence = Some(0.75);

    let log = render_to_string(&r).expect("render SARIF");
    assert!(log.contains("\"rank\": 75"), "got: {log}");
}

#[test]
fn suppressions_are_absent_when_not_suppressed() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(!log.contains("\"suppressions\""), "got: {log}");
}

#[test]
fn suppressions_present_when_finding_suppressed() {
    let mut r = sample_result();
    r.findings[0].suppressed = true;

    let log = render_to_string(&r).expect("render SARIF");
    assert!(log.contains("\"suppressions\""), "got: {log}");
    assert!(log.contains("\"kind\": \"external\""), "got: {log}");
}

#[test]
fn invocations_block_present() {
    let log = render_to_string(&sample_result()).expect("render SARIF");
    assert!(log.contains("\"invocations\""), "got: {log}");
    assert!(log.contains("\"endTimeUtc\""), "got: {log}");
}

#[test]
fn invocation_includes_suppressed_count_when_present() {
    let mut result = sample_result();
    result.suppressed_count = 2;

    let log = render_to_string(&result).expect("render SARIF");

    assert!(log.contains("\"suppressedFindings\": 2"), "got: {log}");
}

#[test]
fn evidence_maps_to_codehound_evidence_property() {
    let mut r = sample_result();
    r.findings[0].evidence = Some(DetectorEvidence::TaintFlow {
        source: codehound::rules::TaintSourceInfo {
            kind: "UserInput".to_string(),
            function: "r.URL.Query".to_string(),
            variable: "host".to_string(),
        },
        sink: codehound::rules::TaintSinkInfo::new("CommandExec", "exec.Command"),
        hops: 1,
        sanitized: false,
    });

    let log = render_to_string(&r).expect("render SARIF");
    assert!(log.contains("\"codehoundEvidence\""), "got: {log}");
    assert!(log.contains("\"kind\": \"TaintFlow\""), "got: {log}");
    assert!(log.contains("\"function\": \"exec.Command\""), "got: {log}");
}

#[test]
fn remediation_maps_to_properties_remediation() {
    let mut r = sample_result();
    r.findings[0].remediation = Some("Use parameterized queries.".to_string());

    let log = render_to_string(&r).expect("render SARIF");
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

    let log = render_to_string(&r).expect("render SARIF");
    let tags_start = log.find("\"tags\"").expect("tags property");
    let tags_section = &log[tags_start..tags_start + 200];
    assert!(tags_section.contains("\"needs-review\""), "got: {log}");
    assert!(
        tags_section.contains("\"false-positive-risk\""),
        "got: {log}"
    );
}

#[test]
fn taint_show_paths_sets_sarif_property_flag() {
    let mut r = sample_result();
    r.findings[0].evidence = Some(DetectorEvidence::TaintFlow {
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
                file: "a.go".into(),
                line: 1,
            }],
        },
        hops: 1,
        sanitized: false,
    });

    let log = render_to_string(&r).expect("render SARIF");
    assert!(
        log.contains("\"codehoundTaintShowPaths\": true"),
        "got: {log}"
    );
}
