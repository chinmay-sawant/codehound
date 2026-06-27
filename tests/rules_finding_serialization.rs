use std::borrow::Cow;

use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

#[test]
fn cwe_serializes_as_empty_array_for_none() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"cwe\":[]"), "expected 'cwe':[], got: {s}");
}

#[test]
fn optional_fields_omitted_when_unset() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
    let s = serde_json::to_string(&f).unwrap();
    assert!(
        !s.contains("end_line"),
        "end_line must be skipped when None"
    );
    assert!(
        !s.contains("byte_offset"),
        "byte_offset must be skipped when None"
    );
    assert!(
        !s.contains("fingerprint"),
        "fingerprint field must be skipped when None"
    );
    assert!(
        !s.contains("evidence"),
        "evidence must be skipped when None"
    );
    assert!(
        !s.contains("confidence"),
        "confidence must be skipped when None"
    );
    assert!(!s.contains("tags"), "tags must be skipped when None");
    assert!(
        !s.contains("suppressed"),
        "suppressed must be skipped when false"
    );
    assert!(
        !s.contains("remediation"),
        "remediation must be skipped when None"
    );
}

#[test]
fn byte_range_appears_in_json() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ))
    .with_byte_range(42, 7);
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"byte_offset\":42"), "got: {s}");
    assert!(s.contains("\"byte_length\":7"), "got: {s}");
}

#[test]
fn end_position_appears_in_json() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ))
    .with_end(3, 5);
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"end_line\":3"), "got: {s}");
    assert!(s.contains("\"end_column\":5"), "got: {s}");
}

#[test]
fn function_range_appears_in_json() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol {
            line: 12,
            column: 5,
        },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ))
    .with_function_range(0, 200, 1, 25);
    let s = serde_json::to_string(&f).unwrap();
    assert!(s.contains("\"function_start_byte\":0"), "got: {s}");
    assert!(s.contains("\"function_end_byte\":200"), "got: {s}");
    assert!(s.contains("\"function_start_line\":1"), "got: {s}");
    assert!(s.contains("\"function_end_line\":25"), "got: {s}");
}
