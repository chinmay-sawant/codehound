#![cfg(feature = "go")]

use slopguard::lang::go::detectors::cwe::common::{
    argument_uses_identifier, has_canonical_path_guard, has_symlink_guard, is_path_confined,
};
use slopguard::lang::go::detectors::cwe::facts::AssignmentFact;
use slopguard::lang::go::detectors::cwe::source_index::SourceIndex;

#[test]
fn has_canonical_path_guard_matches_known_pattern() {
    let src = r#"if strings.HasPrefix(p, "/safe/") { filepath.Abs(p) }"#;
    let index = SourceIndex::build(src);
    assert!(has_canonical_path_guard(&index, src, "p"));
}

#[test]
fn has_symlink_guard_matches_known_pattern() {
    let src = r#"if os.Lstat(p) && os.ModeSymlink { return }"#;
    let index = SourceIndex::build(src);
    assert!(has_symlink_guard(&index, src, "p"));
}

#[test]
fn is_path_confined_recognises_filepath_clean() {
    let a = AssignmentFact {
        name: "p".into(),
        expr: r#"filepath.Clean(p)"#.into(),
        start_byte: 0,
    };
    let src = r#"if strings.HasPrefix(p, "/safe/") { return p }"#;
    let index = SourceIndex::build(src);
    assert!(is_path_confined(&index, src, &a));
}

#[test]
fn argument_uses_identifier_exact_match() {
    assert!(argument_uses_identifier("path", "path"));
}

#[test]
fn argument_uses_identifier_substring_in_call() {
    assert!(argument_uses_identifier(
        "filepath.Join(base, path)",
        "path"
    ));
}

#[test]
fn argument_uses_identifier_no_match() {
    assert!(!argument_uses_identifier("otherVar", "path"));
}

#[test]
fn argument_uses_identifier_underscore_not_split() {
    assert!(!argument_uses_identifier("user_name", "user"));
}

#[test]
fn argument_uses_identifier_empty_argument() {
    assert!(!argument_uses_identifier("", "path"));
}

#[test]
fn argument_uses_identifier_dot_separated() {
    assert!(argument_uses_identifier("v.Name", "v"));
    assert!(argument_uses_identifier("v.Name", "Name"));
}

#[test]
fn source_index_build_and_has() {
    let source = "os.ReadFile(path)\nfilepath.Join(base, name)\nos.Open(file)";
    let index = SourceIndex::build(source);
    assert!(index.has("os.ReadFile"));
    assert!(!index.has("os.WriteFile("));
}
