//! Go CWE detector regression tests — per-CWE evidence assertions.

#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::engine::Analyzer;
use slopguard::rules::DetectorEvidence;

#[test]
fn cwe_78_finding_includes_dangerous_call_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/stdlib/CWE-78-vulnerable.txt");
    let analyzer = Analyzer::builder().build();
    let result = analyzer.analyze_paths([&source_path], None).unwrap();

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
fn cwe_22_finding_includes_dangerous_call_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/stdlib/CWE-22-vulnerable.txt");
    let analyzer = Analyzer::builder().build();
    let result = analyzer.analyze_paths([&source_path], None).unwrap();

    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "CWE-22")
        .unwrap_or_else(|| panic!("CWE-22 finding missing: {:?}", result.findings));

    assert!(matches!(
        finding.evidence,
        Some(DetectorEvidence::DangerousCall {
            ref function,
            argument_index: _,
        }) if is_path_traversal_sink(function)
    ));
}

#[test]
fn cwe_89_finding_includes_dangerous_call_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/stdlib/CWE-89-vulnerable.txt");
    let analyzer = Analyzer::builder().build();
    let result = analyzer.analyze_paths([&source_path], None).unwrap();

    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "CWE-89")
        .unwrap_or_else(|| panic!("CWE-89 finding missing: {:?}", result.findings));

    assert!(matches!(
        finding.evidence,
        Some(DetectorEvidence::DangerousCall {
            ref function,
            argument_index: _,
        }) if is_sql_sink(function)
    ));
}

fn is_path_traversal_sink(function: &str) -> bool {
    matches!(
        function,
        "os.Open" | "os.OpenFile" | "os.ReadFile" | "os.Create" | "ioutil.ReadFile"
    )
}

fn is_sql_sink(function: &str) -> bool {
    matches!(
        function,
        "db.Query"
            | "db.Exec"
            | "db.QueryRow"
            | "db.QueryContext"
            | "db.QueryRowContext"
            | "db.ExecContext"
    )
}
