use std::borrow::Cow;

use slopguard::rules::{Finding, Fingerprint, LineCol, Severity};

fn finding(file: &str, line: usize, column: usize) -> Finding {
    Finding::new(
        "CWE-22",
        "Path traversal",
        file,
        LineCol { line, column },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    )
}

#[test]
fn fingerprint_from_finding_is_deterministic() {
    let f = finding("pkg/handler/user.go", 42, 5);

    assert_eq!(
        f.fingerprint_string(),
        "slopguard:1:CWE-22:pkg/handler/user.go:42:5"
    );
    assert_eq!(f.fingerprint(), f.fingerprint());
}

#[test]
fn different_columns_produce_different_fingerprints() {
    let left = finding("pkg/handler/user.go", 42, 5);
    let right = finding("pkg/handler/user.go", 42, 6);

    assert_ne!(left.fingerprint(), right.fingerprint());
}

#[test]
fn different_files_produce_different_fingerprints() {
    let left = finding("pkg/handler/user.go", 42, 5);
    let right = finding("pkg/handler/admin.go", 42, 5);

    assert_ne!(left.fingerprint(), right.fingerprint());
}

#[test]
fn fingerprint_parse_round_trips() {
    let raw = "slopguard:1:CWE-22:pkg/handler/user.go:42:5";
    let parsed = Fingerprint::parse(raw).unwrap();

    assert_eq!(parsed.to_string(), raw);
    assert_eq!(parsed.rule_id, "CWE-22");
    assert_eq!(parsed.file, "pkg/handler/user.go");
    assert_eq!(parsed.line, 42);
    assert_eq!(parsed.column, 5);
}

#[test]
fn fingerprint_normalizes_windows_path_separators() {
    let f = finding(r"pkg\handler\user.go", 42, 5);

    assert_eq!(
        f.fingerprint_string(),
        "slopguard:1:CWE-22:pkg/handler/user.go:42:5"
    );
}

#[test]
fn fingerprint_handles_unicode_file_paths() {
    let f = finding("pkg/हैंडलर/user.go", 42, 5);

    assert_eq!(
        f.fingerprint_string(),
        "slopguard:1:CWE-22:pkg/हैंडलर/user.go:42:5"
    );
}

#[test]
fn fingerprint_parse_rejects_invalid_prefix() {
    let err = Fingerprint::parse("CWE-22:pkg/handler/user.go:42:5").unwrap_err();

    assert!(err.to_string().contains("must start with slopguard:1:"));
}
