//! Go bad-practice project-fixture regression tests.

#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::engine::Analyzer;
use std::fs;
use std::path::Path;

fn discover_project_cases() -> Vec<String> {
    let root = Path::new("tests/fixtures/go/bad_practices_projects");
    let mut cases = Vec::new();
    for entry in fs::read_dir(root).unwrap_or_else(|e| panic!("read_dir {}: {e}", root.display())) {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();
        if let Some(case) = name.strip_suffix("-vulnerable") {
            cases.push(case.to_string());
        }
    }
    cases.sort();
    cases
}

fn analyzer() -> Analyzer {
    Analyzer::builder().with_default_filter().build()
}

#[test]
fn go_bad_practice_project_fixtures_fire_vulnerable_and_silence_safe() {
    let analyzer = analyzer();
    let cases = discover_project_cases();
    let mut failures = Vec::new();

    for case in cases {
        let vulnerable = format!("tests/fixtures/go/bad_practices_projects/{case}-vulnerable");
        let safe = format!("tests/fixtures/go/bad_practices_projects/{case}-safe");
        let expected_rule = case.clone();

        let vulnerable_result = analyzer
            .analyze_paths(&[Path::new(&vulnerable)], None)
            .unwrap_or_else(|e| panic!("analyze {vulnerable}: {e:#}"));
        let vulnerable_ids: Vec<&str> = vulnerable_result
            .findings
            .iter()
            .map(|f| f.rule_id)
            .collect();
        if !vulnerable_ids.contains(&expected_rule.as_str()) {
            failures.push(format!(
                "{vulnerable}: expected {expected_rule}, got {vulnerable_ids:?}"
            ));
        }

        let safe_result = analyzer
            .analyze_paths(&[Path::new(&safe)], None)
            .unwrap_or_else(|e| panic!("analyze {safe}: {e:#}"));
        let safe_ids: Vec<&str> = safe_result.findings.iter().map(|f| f.rule_id).collect();
        if safe_ids.iter().any(|rule_id| rule_id.starts_with("BP-")) {
            failures.push(format!("{safe}: expected no BP findings, got {safe_ids:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "project BP fixture failures: {failures:#?}"
    );
}
