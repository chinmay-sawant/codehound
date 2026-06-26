use std::borrow::Cow;

use slopguard::cwe::CweRef;
use slopguard::rules::{Finding, LineCol, Severity};

#[test]
fn new_builds_finding_with_no_snippet_or_fix() {
    let f = Finding::new(
        "CWE-89",
        "title",
        "a.go",
        LineCol { line: 1, column: 1 },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    );
    assert_eq!(f.rule_id, "CWE-89");
    assert_eq!(f.rule_title, "title");
    assert_eq!(f.file, "a.go");
    assert_eq!(f.line, 1);
    assert_eq!(f.column, 1);
    assert_eq!(f.message, "msg");
    assert_eq!(f.severity, Severity::High);
    assert!(f.snippet.is_none());
    assert!(f.fix.is_none());
    assert!(f.cwe.is_none());
    assert!(f.evidence.is_none());
    assert!(f.confidence.is_none());
    assert!(f.tags.is_none());
    assert!(!f.suppressed);
    assert!(f.remediation.is_none());
}

#[test]
fn empty_cwe_slice_compiles_to_none() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    assert!(f.cwe.is_none(), "empty slice must collapse to None");
}

#[test]
fn cwe_slice_with_entries_is_some() {
    let refs: &'static [CweRef] =
        Box::leak(Box::new([CweRef::new(89, "x", "https://example.com/89")]));
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(refs),
    );
    let cwes = f.cwe.expect("non-empty slice must produce Some");
    assert_eq!(cwes.len(), 1);
    assert_eq!(cwes[0].id, 89);
}

#[test]
fn with_snippet_and_with_fix_chain() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    )
    .with_snippet("the snippet")
    .with_fix("the fix");
    assert_eq!(f.snippet.as_deref(), Some("the snippet"));
    assert_eq!(f.fix.as_deref(), Some("the fix"));
}

#[test]
fn file_accepts_string_or_str() {
    let owned: String = String::from("owned.go");
    let _ = Finding::new(
        "X",
        "t",
        owned,
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    let _ = Finding::new(
        "X",
        "t",
        "borrowed.go",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
}
