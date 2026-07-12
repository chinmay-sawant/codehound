use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

use codehound::reporting::text::{TextOptions, write_with_options};
use insta::assert_snapshot;

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
fn text_summary_snapshot_is_stable() {
    let sample = sample_result();
    let mut buf = Vec::new();
    write_with_options(
        &mut buf,
        &sample,
        TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert_snapshot!("text_summary", s);
}
