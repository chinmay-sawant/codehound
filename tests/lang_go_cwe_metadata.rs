#![cfg(feature = "go")]

#[path = "helpers/go_cwe_cases.rs"]
mod go_cwe_cases;

use slopguard::core::Detector;
use slopguard::cwe::builtin_rule_catalogue;
use slopguard::engine::Analyzer;
use slopguard::fixture::materialize_fixture;
use slopguard::lang::go::detectors::cwe::GoCweScan;

#[test]
fn go_cwe_metadata_runtime_stays_aligned() {
    let fixture_ids = go_cwe_cases::discover_go_cwe_cases();
    let detector = GoCweScan;
    let detector_ids = detector
        .rule_ids()
        .iter()
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();

    assert_eq!(
        detector_ids, fixture_ids,
        "detector rule ids drifted from fixtures"
    );

    for rule_id in &fixture_ids {
        let metadata = detector
            .metadata_for(rule_id)
            .unwrap_or_else(|| panic!("missing metadata for {rule_id}"));
        assert_eq!(metadata.id, rule_id);
        assert!(
            !metadata.title.is_empty(),
            "{rule_id} title should not be empty"
        );
        assert!(
            !metadata.description.is_empty(),
            "{rule_id} description should not be empty"
        );
        assert_eq!(
            metadata.cwe.len(),
            1,
            "{rule_id} should carry exactly one structured CWE ref"
        );
        assert_eq!(
            metadata.cwe[0].id,
            go_cwe_cases::parse_cwe_number(rule_id),
            "{rule_id} structured CWE id mismatch"
        );
        assert_eq!(
            metadata.cwe[0].name, metadata.title,
            "{rule_id} structured CWE title mismatch"
        );
    }
}

#[test]
fn builtin_catalogue_covers_all_go_fixture_rules() {
    let rule_ids = builtin_rule_catalogue()
        .iter()
        .map(|entry| canonicalize_rule_id(&entry.id))
        .collect::<std::collections::HashSet<_>>();

    for cwe in go_cwe_cases::discover_go_cwe_cases() {
        assert!(
            rule_ids.contains(&cwe),
            "builtin_rule_catalogue is missing {cwe}"
        );
    }
}

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

fn canonicalize_rule_id(id: &str) -> String {
    if id.starts_with("CWE-") {
        id.to_string()
    } else {
        format!("CWE-{id}")
    }
}
