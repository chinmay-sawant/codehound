use std::borrow::Cow;

use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

fn finding(file: &str, line: usize, column: usize) -> Finding {
    Finding::new(FindingInputs::new(
        "CWE-22",
        "Path traversal",
        file,
        LineCol { line, column },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    ))
}

#[test]
fn fingerprint_from_finding_is_deterministic() {
    let f = finding("pkg/handler/user.go", 42, 5);

    assert_eq!(
        f.fingerprint_string(),
        "slopguard:1:CWE-22:pkg/handler/user.go:42:5"
    );
    assert_eq!(f.fingerprint_string(), f.fingerprint_string());
}

#[test]
fn different_columns_produce_different_fingerprints() {
    let left = finding("pkg/handler/user.go", 42, 5);
    let right = finding("pkg/handler/user.go", 42, 6);

    assert_ne!(left.fingerprint_string(), right.fingerprint_string());
}

#[test]
fn different_files_produce_different_fingerprints() {
    let left = finding("pkg/handler/user.go", 42, 5);
    let right = finding("pkg/handler/admin.go", 42, 5);

    assert_ne!(left.fingerprint_string(), right.fingerprint_string());
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
