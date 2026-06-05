#![cfg(feature = "go")]

use slopguard::lang::go::detectors::cwe::common::{
    has_canonical_path_guard, has_symlink_guard, is_path_confined,
};
use slopguard::lang::go::detectors::cwe::facts::AssignmentFact;

#[test]
fn has_canonical_path_guard_matches_known_pattern() {
    let src = r#"if strings.HasPrefix(p, "/safe/") { filepath.Abs(p) }"#;
    assert!(has_canonical_path_guard(src, "p"));
}

#[test]
fn has_symlink_guard_matches_known_pattern() {
    let src = r#"if os.Lstat(p) && os.ModeSymlink { return }"#;
    assert!(has_symlink_guard(src, "p"));
}

#[test]
fn is_path_confined_recognises_filepath_clean() {
    let a = AssignmentFact {
        name: "p".into(),
        expr: r#"filepath.Clean(p)"#.into(),
        start_byte: 0,
    };
    let src = r#"if strings.HasPrefix(p, "/safe/") { return p }"#;
    assert!(is_path_confined(src, &a));
}
