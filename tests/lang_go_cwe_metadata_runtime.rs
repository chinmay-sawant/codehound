#![cfg(feature = "go")]

use slopguard::engine::Analyzer;
use slopguard::fixture::materialize_fixture;

#[test]
fn go_cwe_findings_include_structured_cwe_refs() {
    let fixture = "tests/fixtures/go/frameworks/CWE-22-vulnerable.txt";
    let source_path = materialize_fixture(std::path::Path::new(fixture))
        .unwrap_or_else(|e| panic!("materialize {fixture}: {e:#}"));

    let analyzer = Analyzer::builder().build();
    let result = analyzer
        .analyze_paths([&source_path], None)
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", source_path.display()));

    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "CWE-22")
        .expect("expected CWE-22 finding");
    let cwe = finding
        .cwe
        .as_deref()
        .expect("expected structured CWE metadata");

    assert_eq!(cwe.len(), 1);
    assert_eq!(cwe[0].id, 22);
    assert_eq!(cwe[0].name, finding.rule_title);
    assert_eq!(cwe[0].url, "https://cwe.mitre.org/data/definitions/22.html");
}
