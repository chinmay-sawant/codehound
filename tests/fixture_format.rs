use std::path::Path;

use codehound::fixture::{FixtureLanguage, parse_fixture};

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
    assert!(
        err.to_string().contains("unknown fixture language"),
        "unexpected: {err}"
    );
}
