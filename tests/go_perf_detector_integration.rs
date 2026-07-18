//! Go PERF detector regression tests.
//!
//! Fixture inventory is discovered from `tests/fixtures/go/perf` so the test
//! suite does not need a second hand-maintained list of PERF cases. Base
//! cases (`PERF-038`) and named variants (`PERF-038-done`,
//! `PERF-114-interface`) are both discovered, matching the BP fixture layout.
//! We validate both paths that matter:
//! - in-process analyzer scans over materialized sources
//! - CLI scans over the raw `.txt` heuristic fixtures

#[path = "helpers/go_perf_cases.rs"]
mod go_perf_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use codehound::engine::Analyzer;
use codehound::rules::{ControlFlowKind, DetectorEvidence};
use std::process::Command;

fn reported_rule_ids(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.is_empty()
                || trimmed.starts_with("severity:")
                || trimmed.starts_with("top rules:")
            {
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
    let analyzer = Analyzer::builder().build();

    for case in &cases {
        let vulnerable = go_perf_cases::fixture_path(case, true);
        let safe = go_perf_cases::fixture_path(case, false);
        let rule = go_perf_cases::expected_rule_id(case);
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            helpers::assert_fixture_rules(&vulnerable, &[rule.as_str()], &analyzer);
            helpers::assert_fixture_rules(&safe, &[], &analyzer);
        })) {
            failures.push(format!("{case}: {e:?}"));
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
    // Full detector coverage lives in
    // `go_perf_fixtures_fire_vulnerable_and_silence_safe` (in-process).
    // A full CLI matrix was hundreds of process spawns and dominated suite time.
    let cases = go_perf_cases::discover_go_perf_cases();
    let case = cases
        .first()
        .expect("expected at least one Go PERF fixture");
    let vulnerable = go_perf_cases::fixture_path(case, true);
    let safe = go_perf_cases::fixture_path(case, false);
    let expected_rule = go_perf_cases::expected_rule_id(case);
    let exe = env!("CARGO_BIN_EXE_codehound");

    let vulnerable_run = Command::new(exe)
        .args([
            "--profile",
            "perf",
            "--only",
            expected_rule.as_str(),
            "--no-cache",
            vulnerable.as_str(),
        ])
        .output()
        .unwrap_or_else(|e| panic!("run {vulnerable}: {e}"));
    let vulnerable_stdout = String::from_utf8_lossy(&vulnerable_run.stdout);
    let vulnerable_ids = reported_rule_ids(&vulnerable_stdout);
    // Info-tier PERF (B/C) correctly exits 0 under MediumAsErrors; only require
    // the rule to fire. Medium/high findings exit 1.
    assert!(
        vulnerable_ids.contains(&expected_rule.as_str()),
        "{vulnerable}: expected {expected_rule}, got status {:?}, ids {:?}, stdout:\n{}",
        vulnerable_run.status.code(),
        vulnerable_ids,
        vulnerable_stdout
    );

    let safe_run = Command::new(exe)
        .args([
            "--profile",
            "perf",
            "--only",
            expected_rule.as_str(),
            "--no-cache",
            safe.as_str(),
        ])
        .output()
        .unwrap_or_else(|e| panic!("run {safe}: {e}"));
    let safe_stdout = String::from_utf8_lossy(&safe_run.stdout);
    let safe_ids = reported_rule_ids(&safe_stdout);
    assert!(
        !safe_ids.iter().any(|rule_id| rule_id.starts_with("PERF-")),
        "{safe}: expected no PERF findings, got status {:?}, ids {:?}, stdout:\n{}",
        safe_run.status.code(),
        safe_ids,
        safe_stdout
    );
}

#[test]
fn perf_1_finding_includes_control_flow_issue_evidence() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/perf/PERF-001-vulnerable.txt");
    let analyzer = Analyzer::builder().build();
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
fn go_perf_fixture_inventory_is_sorted_and_deduplicated() {
    let cases = go_perf_cases::discover_go_perf_cases();

    assert!(!cases.is_empty(), "expected at least one Go PERF fixture");

    assert!(
        go_perf_cases::is_sorted_and_deduplicated(&cases),
        "Go PERF fixture cases must be sorted and deduplicated: {cases:?}"
    );

    // Named variants must keep a matching base case for the same rule number.
    for case in &cases {
        if let Some((_, Some(_))) = parse_case_for_test(case) {
            let base = base_case_name(case);
            assert!(
                cases.iter().any(|c| c == &base),
                "variant {case} requires base case {base}"
            );
        }
    }
}

fn parse_case_for_test(case: &str) -> Option<(u32, Option<&str>)> {
    let rest = case.strip_prefix("PERF-")?;
    let (number, tail) = rest
        .split_once('-')
        .map_or((rest, None), |(number, tail)| (number, Some(tail)));
    Some((number.parse().ok()?, tail))
}

fn base_case_name(case: &str) -> String {
    let rest = case.strip_prefix("PERF-").expect("PERF- prefix");
    let number = rest.split_once('-').map_or(rest, |(n, _)| n);
    // Preserve the zero-padding used on disk for the base case.
    format!("PERF-{number}")
}
