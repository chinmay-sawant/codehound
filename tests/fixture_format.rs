use std::path::Path;

use slopguard::fixture::{FixtureLanguage, parse_fixture};

#[test]
fn parses_minimal_header() {
    let text = "lang: python\n---\nimport re\n";
    let f = parse_fixture(text, Path::new("sample.txt")).unwrap();
    assert_eq!(f.language, FixtureLanguage::Python);
    assert_eq!(f.filename, "sample.py");
    assert!(f.source.contains("import re"));
}
