use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::reporting::text::{TextOptions, write_with_options};
use slopguard::rules::{DetectorEvidence, Finding, LineCol, Severity};

#[test]
fn empty_result_renders_summary() {
    let r = AnalysisResult::default();
    let mut out = Vec::new();
    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("no slop detected"), "{rendered}");
}

#[test]
fn finding_with_cwe_renders() {
    let r = one_finding_result();
    let mut out = Vec::new();
    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("CWE-89"), "{rendered}");
    assert!(rendered.contains("1 finding"), "{rendered}");
}

#[test]
fn text_output_hides_fingerprint_by_default() {
    let r = one_finding_result();
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(!rendered.contains("fingerprint:"), "{rendered}");
    assert!(
        !rendered.contains("slopguard:1:CWE-89:a.go:1:1"),
        "{rendered}"
    );
}

#[test]
fn text_output_can_show_fingerprint() {
    let r = one_finding_result();
    let mut out = Vec::new();

    write_with_options(
        &mut out,
        &r,
        TextOptions {
            show_fingerprint: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(
        rendered.contains("fingerprint: slopguard:1:CWE-89:a.go:1:1"),
        "{rendered}"
    );
}

#[test]
fn text_output_shows_metadata_without_raw_evidence_by_default() {
    let r = one_structured_finding_result();
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("confidence: 0.75"), "{rendered}");
    assert!(
        rendered.contains("tags: needs-review, heuristic"),
        "{rendered}"
    );
    assert!(rendered.contains("status: suppressed"), "{rendered}");
    assert!(!rendered.contains("evidence:"), "{rendered}");
    assert!(!rendered.contains("exec.Command"), "{rendered}");
}

#[test]
fn verbose_text_output_shows_evidence_summary() {
    let r = one_structured_finding_result();
    let mut out = Vec::new();

    write_with_options(
        &mut out,
        &r,
        TextOptions {
            verbose: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(
        rendered.contains("evidence: dangerous call `exec.Command` argument 0"),
        "{rendered}"
    );
}

#[test]
fn text_output_hides_full_confidence() {
    let mut r = one_finding_result();
    r.findings[0].confidence = Some(1.0);
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(!rendered.contains("confidence:"), "{rendered}");
}

fn one_finding_result() -> AnalysisResult {
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        )],
        errors: vec![],
        suppressed_count: 0,
    }
}

fn one_structured_finding_result() -> AnalysisResult {
    let finding = Finding::new(
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
    )
    .with_evidence(DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(0),
    })
    .with_confidence(0.75)
    .with_tags(vec!["needs-review".to_string(), "heuristic".to_string()])
    .mark_suppressed();

    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![finding],
        errors: vec![],
        suppressed_count: 1,
    }
}
