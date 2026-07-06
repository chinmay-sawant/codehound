#![cfg(feature = "go")]

use codehound::lang::go::detectors::cwe::common::{
    has_canonical_path_guard, has_symlink_guard, is_path_confined,
};
use codehound::lang::go::detectors::cwe::facts::AssignmentFact;
use codehound::lang::go::detectors::cwe::source_index::{NEEDLES, SourceIndex};

#[test]
fn has_canonical_path_guard_matches_known_pattern() {
    let src = r#"if strings.HasPrefix(p, "/safe/") { filepath.Abs(p) }"#;
    let index = SourceIndex::build(NEEDLES, src);
    assert!(has_canonical_path_guard(&index, src, "p"));
}

#[test]
fn has_symlink_guard_matches_known_pattern() {
    let src = r#"if os.Lstat(p) && os.ModeSymlink { return }"#;
    let index = SourceIndex::build(NEEDLES, src);
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
    let index = SourceIndex::build(NEEDLES, src);
    assert!(is_path_confined(&index, src, &a));
}

#[test]
fn source_index_build_and_has() {
    let source = "os.ReadFile(path)\nfilepath.Join(base, name)\nos.Open(file)";
    let index = SourceIndex::build(NEEDLES, source);
    assert!(index.has("os.ReadFile"));
    assert!(!index.has("os.WriteFile("));
}
