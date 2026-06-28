//! Go PERF detector regression tests.
//!
//! Fixture inventory is discovered from `tests/fixtures/go/perf` so the test
//! suite does not need a second hand-maintained list of PERF ids.

#[path = "helpers/go_perf_cases.rs"]
mod go_perf_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::engine::Analyzer;
use slopguard::rules::{ControlFlowKind, DetectorEvidence};

#[test]
fn go_perf_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_perf_cases::discover_go_perf_cases();
    let mut failures: Vec<String> = Vec::new();

    for perf_id in &cases {
        let vulnerable = go_perf_cases::fixture_path(*perf_id, true);
        let safe = go_perf_cases::fixture_path(*perf_id, false);
        let rule = format!("PERF-{perf_id}");
        let analyzer = Analyzer::builder().with_default_filter().build();
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            helpers::assert_fixture_rules(&vulnerable, &[rule.as_str()], &analyzer);
            helpers::assert_fixture_rules(&safe, &[], &analyzer);
        })) {
            failures.push(format!("PERF-{perf_id}: {e:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} PERF fixtures failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn perf_1_finding_includes_control_flow_issue_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/perf/PERF-001-vulnerable.txt");
    let analyzer = Analyzer::builder().with_default_filter().build();
    let result = analyzer.analyze_paths(&[&source_path], None).unwrap();

    let finding = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "PERF-1")
        .unwrap_or_else(|| panic!("PERF-1 finding missing: {:?}", result.findings));

    assert!(matches!(
        finding.evidence,
        Some(DetectorEvidence::ControlFlowIssue {
            control_flow_kind: ControlFlowKind::LoopBodyAllocation,
            location: _,
        })
    ));
}

#[test]
fn go_perf_fixture_inventory_is_sorted_and_contiguous() {
    let cases = go_perf_cases::discover_go_perf_cases();

    assert!(!cases.is_empty(), "expected at least one Go PERF fixture");

    assert!(
        cases.windows(2).all(|w| w[0] < w[1]),
        "Go PERF fixture ids must be sorted and deduplicated"
    );
}
