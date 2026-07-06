//! Go CWE detector regression tests — fixture inventory and taint sweep.

#[path = "helpers/go_cwe_cases.rs"]
mod go_cwe_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;

#[test]
fn go_cwe_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_cwe_cases::discover_go_cwe_cases();
    let mut failures: Vec<String> = Vec::new();

    for cwe in &cases {
        for suite in ["frameworks", "stdlib"] {
            let vulnerable = go_cwe_cases::fixture_path(suite, cwe, true);
            let safe = go_cwe_cases::fixture_path(suite, cwe, false);
            let analyzer = Analyzer::builder().build();
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                helpers::assert_fixture_rules(&vulnerable, &[cwe.as_str()], &analyzer);
                helpers::assert_fixture_rules(&safe, &[], &analyzer);
            })) {
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

#[test]
fn taint_cwe_fixtures_fire_vulnerable_and_silence_safe() {
    let ctx = ScanContext {
        taint_enabled: true,
        ..ScanContext::default()
    };
    let analyzer = Analyzer::builder()
        
        .scan_context(ctx)
        .build();

    for cwe in ["CWE-78", "CWE-89", "CWE-22", "CWE-79"] {
        let vulnerable = helpers::assert_fixture_materializes(&format!(
            "tests/fixtures/go/taint/{cwe}-vulnerable.txt"
        ));
        let safe = helpers::assert_fixture_materializes(&format!(
            "tests/fixtures/go/taint/{cwe}-safe.txt"
        ));

        let vuln_result = analyzer.analyze_paths(&[&vulnerable], None).unwrap();
        assert!(
            vuln_result.findings.iter().any(|f| f.rule_id == cwe),
            "{cwe} taint vulnerable fixture should fire"
        );

        let safe_result = analyzer.analyze_paths(&[&safe], None).unwrap();
        assert!(
            !safe_result.findings.iter().any(|f| f.rule_id == cwe),
            "{cwe} taint safe fixture should be silent, got {:?}",
            safe_result.findings
        );
    }
}

#[test]
fn framework_cwe_393_safe_does_not_false_positive_cwe_89() {
    let ctx = ScanContext {
        taint_enabled: true,
        ..ScanContext::default()
    };
    let analyzer = Analyzer::builder()
        
        .scan_context(ctx)
        .build();
    let safe =
        helpers::assert_fixture_materializes("tests/fixtures/go/frameworks/CWE-393-safe.txt");

    let result = analyzer.analyze_paths(&[&safe], None).unwrap();
    assert!(
        !result.findings.iter().any(|f| f.rule_id == "CWE-89"),
        "framework CWE-393 safe fixture should not emit CWE-89, got {:?}",
        result.findings
    );
}
