//! Go bad-practice project-fixture regression tests.

#[path = "helpers/mod.rs"]
mod helpers;

use codehound::engine::Analyzer;
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

/// `BP-47` and `BP-47-fiber` both expect rule `BP-47` (same layout as text BP variants).
fn expected_rule_id(case: &str) -> String {
    let rest = case
        .strip_prefix("BP-")
        .unwrap_or_else(|| panic!("invalid project BP case: {case}"));
    let number = rest
        .split('-')
        .next()
        .unwrap_or_else(|| panic!("invalid project BP case number: {case}"));
    format!("BP-{number}")
}

fn analyzer() -> Analyzer {
    Analyzer::builder().build()
}

#[test]
fn go_bad_practice_project_fixtures_fire_vulnerable_and_silence_safe() {
    let analyzer = analyzer();
    let cases = discover_project_cases();
    let mut failures = Vec::new();

    for case in cases {
        let vulnerable = format!("tests/fixtures/go/bad_practices_projects/{case}-vulnerable");
        let safe = format!("tests/fixtures/go/bad_practices_projects/{case}-safe");
        let expected_rule = expected_rule_id(&case);

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

#[test]
fn library_example_server_does_not_trigger_project_server_rules() {
    let root = helpers::unique_temp_root("library-example-server");
    fs::create_dir_all(&root).unwrap_or_else(|e| panic!("create {}: {e}", root.display()));
    fs::write(
        root.join("go.mod"),
        "module example.com/library-with-examples\n\ngo 1.24.0\n",
    )
    .unwrap_or_else(|e| panic!("write go.mod: {e}"));
    for fixture in [
        "tests/fixtures/go/bad_practices_project_text/library.txt",
        "tests/fixtures/go/bad_practices_project_text/example_server.txt",
        "tests/fixtures/go/bad_practices_project_text/comment_only_server.txt",
    ] {
        let text = fs::read_to_string(fixture).unwrap_or_else(|e| panic!("read {fixture}: {e}"));
        let parsed = codehound::fixture::parse_fixture(&text, Path::new(fixture))
            .unwrap_or_else(|e| panic!("parse {fixture}: {e}"));
        let output = root.join(parsed.filename);
        fs::create_dir_all(output.parent().unwrap())
            .unwrap_or_else(|e| panic!("create {}: {e}", output.display()));
        fs::write(&output, parsed.source)
            .unwrap_or_else(|e| panic!("write {}: {e}", output.display()));
    }

    let result = analyzer()
        .analyze_paths(&[&root], None)
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", root.display()));
    let _ = fs::remove_dir_all(&root);
    let server_rule_findings: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.rule_id)
        .filter(|rule_id| matches!(*rule_id, "BP-47" | "BP-50" | "BP-54" | "BP-55"))
        .collect();

    assert!(
        server_rule_findings.is_empty(),
        "example servers must not make a library a server application: {server_rule_findings:?}"
    );
}
