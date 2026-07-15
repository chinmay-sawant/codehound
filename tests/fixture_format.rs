use std::path::Path;

use codehound::fixture::{
    FixtureError, FixtureLanguage, materialize_fixture, materialize_tree, parse_fixture,
};

#[test]
fn parses_minimal_header() {
    let text = "lang: python\n---\nimport re\n";
    let f = parse_fixture(text, Path::new("sample.txt")).unwrap();
    assert_eq!(f.language, FixtureLanguage::Python);
    assert_eq!(f.filename, "sample.py");
    assert!(f.source.contains("import re"));
}

#[test]
fn rejects_unsupported_fixture_language_rust() {
    // FixtureLanguage only knows go/python — no silent "lang: rust" partial support.
    let text = "lang: rust\n---\nfn main() {}\n";
    let err = parse_fixture(text, Path::new("x.txt")).unwrap_err();
    assert!(matches!(err, FixtureError::UnknownLanguage(language) if language == "rust"));
}

#[test]
fn missing_fixture_file_returns_typed_io_error() {
    let path = Path::new("target/codehound-missing-fixture.txt");
    let err = materialize_fixture(path).unwrap_err();
    assert!(matches!(err, FixtureError::Io { .. }));
}

#[test]
fn missing_fixture_tree_returns_typed_walk_error() {
    let path = Path::new("target/codehound-missing-fixture-tree");
    let err = materialize_tree(path).unwrap_err();
    assert!(matches!(err, FixtureError::Walk(_)));
}
