//! Go PERF detector regression tests.
//!
//! Fixture inventory is discovered from `tests/fixtures/go/perf` so the test
//! suite does not need a second hand-maintained list of PERF ids. We validate
//! both paths that matter:
//! - in-process analyzer scans over materialized sources
//! - CLI scans over the raw `.txt` heuristic fixtures

#[path = "helpers/go_perf_cases.rs"]
mod go_perf_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use slopguard::engine::Analyzer;
use slopguard::rules::{ControlFlowKind, DetectorEvidence};
use std::process::Command;

fn reported_rule_ids(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with("severity:") || trimmed.starts_with("top rules:") {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let _severity = parts.next()?;
            let rule_id = parts.next()?;
            if rule_id.contains('-') {
                Some(rule_id)
            } else {
                None
            }
        })
        .collect()
}

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
fn go_perf_text_fixtures_also_work_via_cli_scan_path() {
    let cases = go_perf_cases::discover_go_perf_cases();
    let mut failures: Vec<String> = Vec::new();
    let exe = env!("CARGO_BIN_EXE_slopguard");

    for perf_id in &cases {
        let vulnerable = go_perf_cases::fixture_path(*perf_id, true);
        let safe = go_perf_cases::fixture_path(*perf_id, false);
        let expected_rule = format!("PERF-{perf_id}");

        let vulnerable_run = Command::new(exe)
            .args(["scan", vulnerable.as_str()])
            .output()
            .unwrap_or_else(|e| panic!("run {vulnerable}: {e}"));
        let vulnerable_stdout = String::from_utf8_lossy(&vulnerable_run.stdout);
        let vulnerable_ids = reported_rule_ids(&vulnerable_stdout);
        if vulnerable_run.status.code() != Some(1) || !vulnerable_ids.contains(&expected_rule.as_str()) {
            failures.push(format!(
                "{vulnerable}: expected exit 1 and {expected_rule}, got status {:?}, ids {:?}, stdout:\n{}",
                vulnerable_run.status.code(),
                vulnerable_ids,
                vulnerable_stdout
            ));
        }

        let safe_run = Command::new(exe)
            .args(["scan", safe.as_str()])
            .output()
            .unwrap_or_else(|e| panic!("run {safe}: {e}"));
        let safe_stdout = String::from_utf8_lossy(&safe_run.stdout);
        let safe_ids = reported_rule_ids(&safe_stdout);
        if safe_ids.iter().any(|rule_id| rule_id.starts_with("PERF-")) {
            failures.push(format!(
                "{safe}: expected no PERF findings, got status {:?}, ids {:?}, stdout:\n{}",
                safe_run.status.code(),
                safe_ids,
                safe_stdout
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} CLI PERF fixture scans failed: {failures:#?}",
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
