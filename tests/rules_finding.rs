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
    let refs: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
        89,
        "x",
        "https://example.com/89",
    )]));
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

#[test]
fn cwe_serializes_as_empty_array_for_none() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"cwe\":[]"), "expected 'cwe':[], got: {s}");
}

#[test]
fn optional_fields_omitted_when_unset() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    let s = serde_json::to_string(&f).unwrap();
    assert!(!s.contains("end_line"), "end_line must be skipped when None");
    assert!(
        !s.contains("byte_offset"),
        "byte_offset must be skipped when None"
    );
    assert!(
        !s.contains("fingerprint"),
        "fingerprint field must be skipped when None"
    );
}

#[test]
fn byte_range_appears_in_json() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    )
    .with_byte_range(42, 7);
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"byte_offset\":42"), "got: {s}");
    assert!(s.contains("\"byte_length\":7"), "got: {s}");
}

#[test]
fn end_position_appears_in_json() {
    let f = Finding::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    )
    .with_end(3, 5);
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"end_line\":3"), "got: {s}");
    assert!(s.contains("\"end_column\":5"), "got: {s}");
}

#[test]
fn fingerprint_is_stable_across_calls() {
    let f = Finding::new(
        "CWE-22",
        "title",
        "a.go",
        LineCol { line: 12, column: 5 },
        "msg",
        Severity::Info,
        Cow::Borrowed(&[]),
    );
    assert_eq!(f.fingerprint(), "CWE-22:a.go:12:5");
    assert_eq!(f.fingerprint(), "CWE-22:a.go:12:5");
}
