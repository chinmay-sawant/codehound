//! Go CWE detector regression tests.
//!
//! Fixture inventory is discovered from `tests/fixtures/go/{frameworks,stdlib}` so
//! the test suite does not need a second hand-maintained list of CWE ids.

#[path = "helpers/go_cwe_cases.rs"]
mod go_cwe_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::engine::Analyzer;
use slopguard::rules::DetectorEvidence;

#[test]
fn go_cwe_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_cwe_cases::discover_go_cwe_cases();
    let mut failures: Vec<String> = Vec::new();

    for cwe in &cases {
        for suite in ["frameworks", "stdlib"] {
            let vulnerable = go_cwe_cases::fixture_path(suite, cwe, true);
            let safe = go_cwe_cases::fixture_path(suite, cwe, false);
            if let Err(e) = std::panic::catch_unwind(|| {
                helpers::assert_fixture_rules(&vulnerable, &[cwe.as_str()]);
                helpers::assert_fixture_rules(&safe, &[]);
            }) {
                failures.push(format!("{suite}/{cwe}: {e:?}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} CWE fixtures failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn cwe_78_finding_includes_dangerous_call_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/stdlib/CWE-78-vulnerable.txt");
    let analyzer = Analyzer::builder().build();
    let result = analyzer.analyze_paths([&source_path]).unwrap();

    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "CWE-78")
        .unwrap_or_else(|| panic!("CWE-78 finding missing: {:?}", result.findings));

    assert!(matches!(
        finding.evidence,
        Some(DetectorEvidence::DangerousCall {
            ref function,
            argument_index: Some(2),
        }) if function == "exec.Command"
    ));
}

#[test]
fn go_cwe_fixture_inventory_is_sorted_and_unique() {
    let cases = go_cwe_cases::discover_go_cwe_cases();

    assert!(!cases.is_empty(), "expected at least one Go CWE fixture");

    let mut prev = 0;
    for cwe in &cases {
        let num = go_cwe_cases::parse_cwe_number(cwe);
        assert_eq!(
            cwe,
            &format!("CWE-{num}"),
            "fixture id must be canonical: {cwe}"
        );
        assert!(
            num > prev,
            "fixture ids must be strictly increasing: {prev} then {num}"
        );
        prev = num;
    }
}
