use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::reporting::text::print;
use slopguard::rules::{Finding, LineCol, Severity};

#[test]
fn empty_result_renders_summary() {
    let r = AnalysisResult::default();
    assert!(print(&r).is_ok());
}

#[test]
fn finding_with_cwe_renders() {
    let r = AnalysisResult {
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
    };
    assert!(print(&r).is_ok());
}
