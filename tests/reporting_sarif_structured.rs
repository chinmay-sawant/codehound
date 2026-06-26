use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::reporting::sarif::render_to_string;
use slopguard::rules::{DetectorEvidence, Finding, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn bad_practice_results_have_category_and_medium_security_severity() {
    let result = AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(
            "BP-1",
            "Discarded Error Return",
            "bad.go",
            LineCol { line: 3, column: 2 },
            "discarded error",
            Severity::Low,
            Cow::Borrowed(&[]),
        )],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    };

    let log = render_to_string(&result);

    assert!(log.contains("\"category\": \"bad_practice\""), "got: {log}");
    assert!(log.contains("\"security-severity\": \"5.0\""), "got: {log}");
    assert!(log.contains("\"bad_practice\""), "got: {log}");
}

#[test]
fn invocations_block_present() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(log.contains("\"invocations\""), "got: {log}");
    assert!(log.contains("\"endTimeUtc\""), "got: {log}");
}

#[test]
fn invocation_includes_suppressed_count_when_present() {
    let mut result = helpers::reporting::sample_result();
    result.suppressed_count = 2;

    let log = render_to_string(&result);

    assert!(log.contains("\"suppressedFindings\": 2"), "got: {log}");
}

#[test]
fn evidence_maps_to_slopguard_evidence_property() {
    let mut r = helpers::reporting::sample_result();
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
    let mut r = helpers::reporting::sample_result();
    r.findings[0].remediation = Some("Use parameterized queries.".to_string());

    let log = render_to_string(&r);
    assert!(
        log.contains("\"remediation\": \"Use parameterized queries.\""),
        "got: {log}"
    );
}

#[test]
fn finding_tags_are_included_in_properties_tags() {
    let mut r = helpers::reporting::sample_result();
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
