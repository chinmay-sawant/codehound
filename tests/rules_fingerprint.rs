use std::borrow::Cow;

use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

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

fn finding_msg(file: &str, message: &str) -> Finding {
    Finding::new(FindingInputs::new(
        "CWE-22",
        "Path traversal",
        file,
        LineCol { line: 1, column: 1 },
        message,
        Severity::High,
        Cow::Borrowed(&[]),
    ))
}

#[test]
fn fingerprint_from_finding_is_deterministic() {
    let f = finding("pkg/handler/user.go", 42, 5);
    let fp = f.fingerprint_string();

    assert!(
        fp.starts_with("codehound:2:CWE-22:pkg/handler/user.go:"),
        "got: {fp}"
    );
    assert_eq!(fp, f.fingerprint_string());
}

#[test]
fn different_columns_same_message_share_fingerprint() {
    // v2 is message-stable: line/column drift must not bust the fingerprint.
    let left = finding("pkg/handler/user.go", 42, 5);
    let right = finding("pkg/handler/user.go", 42, 6);

    assert_eq!(left.fingerprint_string(), right.fingerprint_string());
}

#[test]
fn different_messages_produce_different_fingerprints() {
    let left = finding_msg("pkg/handler/user.go", "msg-a");
    let right = finding_msg("pkg/handler/user.go", "msg-b");

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
    let fp = f.fingerprint_string();

    assert!(
        fp.starts_with("codehound:2:CWE-22:pkg/handler/user.go:"),
        "got: {fp}"
    );
}

#[test]
fn fingerprint_handles_unicode_file_paths() {
    let f = finding("pkg/हैंडलर/user.go", 42, 5);
    let fp = f.fingerprint_string();

    assert!(
        fp.starts_with("codehound:2:CWE-22:pkg/हैंडलर/user.go:"),
        "got: {fp}"
    );
}
