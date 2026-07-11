//! Go CWE detector regression tests — per-CWE evidence assertions.
//!
//! Phase 5 oracle bar: line number, exclusive fire for the target rule
//! family, and taint evidence kind for core taint CWEs.

#[path = "helpers/mod.rs"]
mod helpers;

use codehound::core::ScanContext;
use codehound::engine::Analyzer;
use codehound::rules::DetectorEvidence;

fn taint_analyzer() -> Analyzer {
    Analyzer::builder()
        .scan_context(ScanContext {
            taint_enabled: true,
            only: Some(
                ["CWE-22", "CWE-78", "CWE-89"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            ..ScanContext::default()
        })
        .build()
}

fn assert_taint_oracle(path: &str, rule: &str, line_min: usize, sink_ok: impl Fn(&str) -> bool) {
    let source_path = helpers::assert_fixture_materializes(path);
    let analyzer = taint_analyzer();
    let result = analyzer.analyze_paths(&[&source_path], None).unwrap();

    let of_rule: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == rule)
        .collect();
    assert!(
        !of_rule.is_empty(),
        "{rule} finding missing: {:?}",
        result.findings
    );
    // Exclusive fire among the taint-core family for this fixture path.
    let other_core: Vec<_> = result
        .findings
        .iter()
        .filter(|f| {
            matches!(f.rule_id, "CWE-22" | "CWE-78" | "CWE-89") && f.rule_id != rule
        })
        .map(|f| f.rule_id)
        .collect();
    assert!(
        other_core.is_empty(),
        "{path}: expected exclusive {rule}, also saw {other_core:?}"
    );

    let finding = of_rule[0];
    assert!(
        finding.line >= line_min,
        "{rule} line {} expected >= {line_min}",
        finding.line
    );
    assert!(
        matches!(
            &finding.evidence,
            Some(DetectorEvidence::TaintFlow { sink, .. }) if sink_ok(&sink.function)
        ),
        "{rule} expected TaintFlow evidence, got {:?}",
        finding.evidence
    );
}

#[test]
fn cwe_78_finding_includes_dangerous_call_evidence() {
    assert_taint_oracle(
        "tests/fixtures/go/stdlib/CWE-78-vulnerable.txt",
        "CWE-78",
        1,
        |f| f == "exec.Command",
    );
}

#[test]
fn cwe_22_finding_includes_dangerous_call_evidence() {
    assert_taint_oracle(
        "tests/fixtures/go/stdlib/CWE-22-vulnerable.txt",
        "CWE-22",
        1,
        is_path_traversal_sink,
    );
}

#[test]
fn cwe_89_finding_includes_dangerous_call_evidence() {
    assert_taint_oracle(
        "tests/fixtures/go/stdlib/CWE-89-vulnerable.txt",
        "CWE-89",
        1,
        is_sql_sink,
    );
}

fn is_path_traversal_sink(function: &str) -> bool {
    matches!(
        function,
        "os.Open" | "os.OpenFile" | "os.ReadFile" | "os.Create" | "ioutil.ReadFile"
    )
}

fn is_sql_sink(function: &str) -> bool {
    function.ends_with(".Query")
        || function.ends_with(".Exec")
        || function.ends_with(".QueryRow")
}

#[test]
fn cwe_89_renamed_ids_variant_fires_with_taint_evidence() {
    assert_taint_oracle(
        "tests/fixtures/go/taint/CWE-89-renamed-vulnerable.txt",
        "CWE-89",
        1,
        is_sql_sink,
    );
}

#[test]
fn cwe_89_renamed_safe_is_silent() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/taint/CWE-89-renamed-safe.txt");
    let analyzer = taint_analyzer();
    let result = analyzer.analyze_paths(&[&source_path], None).unwrap();
    assert!(
        !result.findings.iter().any(|f| f.rule_id == "CWE-89"),
        "safe parameterized query should not fire CWE-89: {:?}",
        result.findings
    );
}
