#![cfg(feature = "go")]

#[path = "helpers/go_cwe_cases.rs"]
mod go_cwe_cases;

use slopguard::cwe::builtin_rule_catalogue;
use slopguard::engine::Analyzer;
use slopguard::fixture::materialize_fixture;

const GO_CWE_METADATA_RS: &str = include_str!("../src/lang/go/detectors/cwe/metadata.rs");
const GO_CWE_MOD_RS: &str = include_str!("../src/lang/go/detectors/cwe/mod.rs");

#[test]
fn go_cwe_metadata_source_stays_aligned() {
    let fixture_ids = go_cwe_cases::discover_go_cwe_cases();
    let registry_ids = extract_quoted_cwe_ids(go_registry_block());
    let detector_ids = extract_go_rule_ids(GO_CWE_MOD_RS);
    let meta_ids = extract_meta_const_ids(GO_CWE_METADATA_RS);

    assert_eq!(
        registry_ids, fixture_ids,
        "fixture inventory drifted from GO_CWE_RULE_IDS"
    );
    assert_eq!(
        detector_ids, fixture_ids,
        "detector registrations drifted from fixtures"
    );
    assert_eq!(
        meta_ids, fixture_ids,
        "metadata constants drifted from fixtures"
    );
    assert_eq!(
        count_occurrences(GO_CWE_METADATA_RS, "go_cwe_ref_slice!("),
        fixture_ids.len(),
        "expected every Go metadata entry to carry a structured CWE reference"
    );
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
        .analyze_paths([&source_path])
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

fn go_registry_block() -> &'static str {
    let marker = "pub const GO_CWE_RULE_IDS: &[&str] = &[";
    let start = GO_CWE_METADATA_RS
        .find(marker)
        .unwrap_or_else(|| panic!("missing GO_CWE_RULE_IDS in metadata.rs"));
    let rest = &GO_CWE_METADATA_RS[start + marker.len()..];
    let end = rest
        .find("];")
        .unwrap_or_else(|| panic!("unterminated GO_CWE_RULE_IDS in metadata.rs"));
    &rest[..end]
}

fn extract_quoted_cwe_ids(source: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = source;

    while let Some(start) = rest.find("\"CWE-") {
        let after = &rest[start + 1..];
        let end = after
            .find('"')
            .unwrap_or_else(|| panic!("unterminated quoted CWE id in source"));
        ids.push(after[..end].to_string());
        rest = &after[end + 1..];
    }

    ids
}

fn extract_go_rule_ids(source: &str) -> Vec<String> {
    let mut ids = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("(\"CWE-") {
            continue;
        }

        let first_quote = trimmed
            .find("\"CWE-")
            .unwrap_or_else(|| panic!("missing rule id in detector line: {line}"));
        let after = &trimmed[first_quote + 1..];
        let end = after
            .find('"')
            .unwrap_or_else(|| panic!("unterminated rule id in detector line: {line}"));
        ids.push(after[..end].to_string());
    }

    ids
}

fn extract_meta_const_ids(source: &str) -> Vec<String> {
    let mut ids = Vec::new();

    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix("pub(super) const META_CWE_") else {
            continue;
        };
        let end = rest
            .find(':')
            .unwrap_or_else(|| panic!("missing ':' in metadata const line: {line}"));
        ids.push(format!("CWE-{}", &rest[..end]));
    }

    ids
}

fn count_occurrences(source: &str, needle: &str) -> usize {
    source.matches(needle).count()
}

fn canonicalize_rule_id(id: &str) -> String {
    if id.starts_with("CWE-") {
        id.to_string()
    } else {
        format!("CWE-{id}")
    }
}
