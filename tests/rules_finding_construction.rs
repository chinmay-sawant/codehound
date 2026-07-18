use std::borrow::Cow;

use codehound::cwe::CweRef;
use codehound::rules::{
    DetectorEvidence, Finding, FindingInputs, FindingView, LineCol, Severity, category_for_rule_id,
    sarif_family_tag_for_rule_id, sarif_tags_for_finding,
};

#[test]
fn new_builds_finding_with_no_snippet_or_fix() {
    let f = Finding::new(FindingInputs::new(
        "CWE-89",
        "title",
        "a.go",
        LineCol { line: 1, column: 1 },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ));
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
fn finding_read_only_accessors_expose_invariant_fields() {
    let f = Finding::new(FindingInputs::new(
        "CWE-89",
        "title",
        "a.go",
        LineCol { line: 2, column: 3 },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
    .with_end_checked(4, 5)
    .expect("valid end")
    .with_byte_range_checked(10, 20)
    .expect("valid byte range")
    .with_function_range_checked(0, 30, 1, 5)
    .expect("valid function range")
    .with_confidence_checked(0.75)
    .expect("valid confidence")
    .with_snippet("source")
    .with_fix("fix")
    .with_remediation("remediate");

    assert_eq!(f.rule_id(), "CWE-89");
    assert_eq!(f.rule_title(), "title");
    assert_eq!(f.file(), "a.go");
    assert_eq!(f.location(), LineCol { line: 2, column: 3 });
    assert_eq!(f.end_location(), Some(LineCol { line: 4, column: 5 }));
    assert_eq!(f.message(), "msg");
    assert_eq!(f.severity(), Severity::High);
    assert_eq!(f.byte_range(), Some((10, 20)));
    assert_eq!(f.function_byte_range(), Some((0, 30)));
    assert_eq!(f.function_line_range(), Some((1, 5)));
    assert_eq!(f.snippet(), Some("source"));
    assert_eq!(f.fix(), Some("fix"));
    assert!(f.cwe().is_none());
    assert_eq!(f.confidence(), Some(0.75));
    assert!(f.tags().is_none());
    assert!(!f.suppressed());
    assert_eq!(f.remediation(), Some("remediate"));
}

#[test]
fn checked_location_and_optional_ranges_reject_invalid_values() {
    assert!(LineCol::try_new(0, 1).is_none());
    assert!(LineCol::try_new(1, 0).is_none());
    assert!(LineCol::try_new(1, 1).is_some());

    let finding = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 2, column: 3 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
    assert!(finding.clone().with_confidence_checked(f32::NAN).is_err());
    assert!(finding.clone().with_confidence_checked(1.1).is_err());
    assert!(finding.clone().with_confidence_checked(1.0).is_ok());
    assert!(finding.clone().with_end_checked(1, 4).is_err());
    assert!(finding.clone().with_end_checked(2, 3).is_ok());
    assert!(
        finding
            .clone()
            .with_function_range_checked(20, 10, 1, 2)
            .is_err()
    );
    assert!(finding.with_function_range_checked(10, 20, 2, 3).is_ok());
}

#[test]
fn empty_cwe_slice_compiles_to_none() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
    assert!(f.cwe.is_none(), "empty slice must collapse to None");
}

#[test]
fn cwe_slice_with_entries_is_some() {
    let refs: &'static [CweRef] =
        Box::leak(Box::new([CweRef::new(89, "x", "https://example.com/89")]));
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(refs),
    ));
    let cwes = f.cwe.expect("non-empty slice must produce Some");
    assert_eq!(cwes.len(), 1);
    assert_eq!(cwes[0].id, 89);
}

#[test]
fn with_snippet_and_with_fix_chain() {
    let f = Finding::new(FindingInputs::new(
        "X",
        "t",
        "f",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ))
    .with_snippet("the snippet")
    .with_fix("the fix");
    assert_eq!(f.snippet.as_deref(), Some("the snippet"));
    assert_eq!(f.fix.as_deref(), Some("the fix"));
}

#[test]
fn file_accepts_string_or_str() {
    let owned: String = String::from("owned.go");
    let _ = Finding::new(FindingInputs::new(
        "X",
        "t",
        owned,
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
    let _ = Finding::new(FindingInputs::new(
        "X",
        "t",
        "borrowed.go",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Info,
        Cow::Borrowed(&[]),
    ));
}

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

#[test]
fn structured_output_builders_chain_and_serialize() {
    let f = Finding::new(FindingInputs::new(
        "CWE-78",
        "Command injection",
        "cmd.go",
        LineCol {
            line: 12,
            column: 5,
        },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
    .with_evidence(DetectorEvidence::TaintFlow {
        source: codehound::rules::TaintSourceInfo {
            kind: "UserInput".to_string(),
            function: "r.URL.Query".to_string(),
            variable: "host".to_string(),
        },
        sink: codehound::rules::TaintSinkInfo::new("CommandExec", "exec.Command"),
        hops: 1,
        sanitized: false,
    })
    .with_confidence(0.8)
    .with_tags(vec!["needs-review".to_string()])
    .with_remediation("Use a fixed executable and validate arguments.")
    .mark_suppressed();

    assert!(matches!(
        f.evidence,
        Some(DetectorEvidence::TaintFlow {
            ref sink,
            hops: 1,
            ..
        }) if sink.function == "exec.Command"
    ));
    assert_eq!(f.confidence, Some(0.8));
    assert_eq!(f.tags.as_deref(), Some(&["needs-review".to_string()][..]));
    // add_tag appends without duplicating existing tags.
    let mut tagged = f.clone();
    tagged.add_tag("example");
    tagged.add_tag("example");
    tagged.add_tag("needs-review");
    assert_eq!(
        tagged.tags.as_deref(),
        Some(&["needs-review".to_string(), "example".to_string()][..])
    );
    assert!(f.suppressed);
    assert_eq!(
        f.remediation.as_deref(),
        Some("Use a fixed executable and validate arguments.")
    );

    let value: serde_json::Value = serde_json::to_value(&f).unwrap();
    assert_eq!(value["evidence"]["kind"], "TaintFlow");
    assert!((value["confidence"].as_f64().unwrap() - 0.8).abs() < 0.000_001);
    assert_eq!(value["tags"][0], "needs-review");
    assert_eq!(value["suppressed"], true);
    assert_eq!(
        value["remediation"],
        "Use a fixed executable and validate arguments."
    );
}

#[test]
fn finding_category_and_sarif_tags_use_shared_helpers() {
    let f = Finding::new(FindingInputs::new(
        "PERF-213",
        "title",
        "a.go",
        LineCol { line: 1, column: 1 },
        "msg",
        Severity::Medium,
        Cow::Borrowed(&[]),
    ));

    assert_eq!(f.category(), category_for_rule_id("PERF-213"));
    assert_eq!(
        sarif_family_tag_for_rule_id("PERF-213"),
        Some("performance")
    );

    let tags = sarif_tags_for_finding(&f);
    assert!(tags.contains(&"security".to_string()));
    assert!(tags.contains(&"performance".to_string()));

    let view = FindingView::new(&f);
    assert_eq!(view.category(), f.category());
    assert_eq!(view.sarif_tags(), tags);
    assert_eq!(view.fingerprint(), f.fingerprint_string());
}

#[test]
fn serde_roundtrip_uses_shared_wire_shape() {
    let original = Finding::new(FindingInputs::new(
        "CWE-89",
        "SQL injection",
        "a.go",
        LineCol { line: 2, column: 3 },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
    .with_snippet("x := 1")
    .with_fix("use parameterized queries");

    let json = serde_json::to_string(&original).unwrap();
    let roundtrip: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.rule_id, "CWE-89");
    assert_eq!(roundtrip.file, "a.go");
    assert_eq!(roundtrip.line, 2);
    assert_eq!(roundtrip.snippet.as_deref(), Some("x := 1"));
}
