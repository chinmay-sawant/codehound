use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::reporting::text::{TextOptions, write_with_options};
use codehound::rules::{
    DetectorEvidence, Finding, FindingInputs, LineCol, Severity, TaintSinkInfo, TaintSourceInfo,
};

#[path = "helpers/mod.rs"]
mod helpers;

fn one_structured_finding_result() -> AnalysisResult {
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
            kind: "UserInput".to_string(),
            function: "r.URL.Query".to_string(),
            variable: "host".to_string(),
        },
        sink: TaintSinkInfo::new("CommandExec", "exec.Command"),
        hops: 1,
        sanitized: false,
    })
    .with_confidence(0.75)
    .with_tags(vec!["needs-review".to_string(), "heuristic".to_string()])
    .mark_suppressed();

    helpers::reporting::sample_result(vec![finding])
}

fn one_finding_result() -> AnalysisResult {
    helpers::reporting::sample_result(vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "SQL injection",
        "a.go",
        LineCol { line: 1, column: 1 },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ))])
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
        rendered.contains(
            "evidence: taint flow UserInput.r.URL.Query -> CommandExec.exec.Command across 1 hop"
        ),
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
