//! Shared test helpers for reporting tests.

use std::borrow::Cow;

use slopguard::cwe::CweRef;
use slopguard::engine::AnalysisResult;
use slopguard::rules::{DetectorEvidence, Finding, FindingInputs, LineCol, Severity};

pub fn sample() -> AnalysisResult {
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(FindingInputs::new(
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
        ))],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    }
}

pub fn sample_with_cwe() -> AnalysisResult {
    let cwes: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
        89,
        "SQL Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    )]));
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(cwes),
        ))],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    }
}

pub fn sample_result() -> AnalysisResult {
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![
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
        ],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    }
}

pub fn one_finding_result() -> AnalysisResult {
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        ))],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    }
}

pub fn one_structured_finding_result() -> AnalysisResult {
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
        stats: None,
    }
}
