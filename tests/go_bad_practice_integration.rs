//! Go bad-practice detector regression tests.

#[path = "helpers/go_bp_cases.rs"]
mod go_bp_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use clap::Parser;
use slopguard::cli::{Cli, RuleCategory};
use slopguard::core::ScanContext;
use slopguard::engine::{AnalysisResult, Analyzer, PathFilters, SlopguardConfig};
use slopguard::reporting::json::FindingJson;
use slopguard::reporting::sarif::render_to_string;
use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};
use std::borrow::Cow;
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

fn bp_analyzer() -> Analyzer {
    Analyzer::builder()
        .with_default_filter()
        .path_filters(PathFilters {
            exclude_tests: false,
            ..Default::default()
        })
        .build()
}

#[test]
fn go_bad_practice_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_bp_cases::discover_go_bp_cases();
    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let vulnerable = go_bp_cases::fixture_path(case, true);
        let safe = go_bp_cases::fixture_path(case, false);
        let rule = go_bp_cases::expected_rule_id(case);
        let analyzer = bp_analyzer();
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            helpers::assert_fixture_rules(&vulnerable, &[rule.as_str()], &analyzer);
            helpers::assert_fixture_rules(&safe, &[], &analyzer);
        })) {
            failures.push(format!("{case}: {e:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} BP fixtures failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn go_bad_practice_text_fixtures_also_work_via_cli_scan_path() {
    let cases = go_bp_cases::discover_go_bp_cases();
    let mut failures: Vec<String> = Vec::new();
    let exe = env!("CARGO_BIN_EXE_slopguard");

    for case in &cases {
        let vulnerable = go_bp_cases::fixture_path(case, true);
        let safe = go_bp_cases::fixture_path(case, false);
        let expected_rule = go_bp_cases::expected_rule_id(case);

        let vulnerable_run = Command::new(exe)
            .args(["scan", "--include-tests", vulnerable.as_str()])
            .output()
            .unwrap_or_else(|e| panic!("run {vulnerable}: {e}"));
        let vulnerable_stdout = String::from_utf8_lossy(&vulnerable_run.stdout);
        let vulnerable_ids = reported_rule_ids(&vulnerable_stdout);
        if !vulnerable_ids.contains(&expected_rule.as_str()) {
            failures.push(format!(
                "{vulnerable}: expected {expected_rule}, got status {:?}, ids {:?}, stdout:\n{}",
                vulnerable_run.status.code(),
                vulnerable_ids,
                vulnerable_stdout
            ));
        }

        let safe_run = Command::new(exe)
            .args(["scan", "--include-tests", safe.as_str()])
            .output()
            .unwrap_or_else(|e| panic!("run {safe}: {e}"));
        let safe_stdout = String::from_utf8_lossy(&safe_run.stdout);
        let safe_ids = reported_rule_ids(&safe_stdout);
        if safe_ids.iter().any(|rule_id| rule_id.starts_with("BP-")) {
            failures.push(format!(
                "{safe}: expected no BP findings, got status {:?}, ids {:?}, stdout:\n{}",
                safe_run.status.code(),
                safe_ids,
                safe_stdout
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} CLI BP fixture scans failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn go_bad_practice_fixture_inventory_is_sorted_and_deduplicated() {
    let cases = go_bp_cases::discover_go_bp_cases();

    assert!(!cases.is_empty(), "expected at least one Go BP fixture");
    assert!(
        go_bp_cases::is_sorted_and_deduplicated(&cases),
        "Go BP fixture ids must be sorted and deduplicated"
    );
}

#[test]
fn scan_context_can_disable_bad_practice_category() {
    let ctx = ScanContext {
        bad_practices_enabled: false,
        ..Default::default()
    };

    assert!(!ctx.allows("BP-1"));
    assert!(ctx.allows("CWE-89"));
}

#[test]
fn cli_bp_only_sets_bp_prefix_filter() {
    let cli = Cli::try_parse_from(["slopguard", "--bp-only"]).unwrap();
    let ctx = cli.scan_context(None);

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("PERF-1"));
}

#[test]
fn cli_bp_only_overrides_config_disabled_bp() {
    let cli = Cli::try_parse_from(["slopguard", "--bp-only"]).unwrap();
    let cfg = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
[slopguard.bad_practices]
enabled = false
"#,
    )
    .unwrap();
    let ctx = cli.scan_context(Some(cfg));

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("CWE-89"));
}

#[test]
fn cli_no_bp_disables_bad_practice_category() {
    let cli = Cli::try_parse_from(["slopguard", "--no-bp"]).unwrap();
    let ctx = cli.scan_context(None);

    assert!(!ctx.allows("BP-1"));
    assert!(ctx.allows("PERF-1"));
}

#[test]
fn cli_list_rules_accepts_bad_practice_category_filter() {
    let cli = Cli::try_parse_from([
        "slopguard",
        "--list-rules",
        "--rule-category",
        "bad-practice",
    ])
    .unwrap();

    assert!(cli.list_rules);
    assert_eq!(cli.rule_category, Some(RuleCategory::BadPractice));
}

#[test]
fn cli_list_rules_prints_only_bp_rules_for_bad_practice_filter() {
    let exe = env!("CARGO_BIN_EXE_slopguard");
    let run = Command::new(exe)
        .args(["--list-rules", "--rule-category", "bad-practice"])
        .output()
        .unwrap_or_else(|e| panic!("run --list-rules bad-practice: {e}"));
    let stdout = String::from_utf8_lossy(&run.stdout);

    assert!(run.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("category: bad_practice"), "stdout:\n{stdout}");
    assert!(stdout.contains("BP-1"), "stdout:\n{stdout}");
    assert!(!stdout.contains("PERF-"), "stdout:\n{stdout}");
    assert!(!stdout.contains("CWE-"), "stdout:\n{stdout}");
}

#[test]
fn cli_explain_bp_1_uses_generated_metadata() {
    let exe = env!("CARGO_BIN_EXE_slopguard");
    let run = Command::new(exe)
        .args(["--explain", "BP-1"])
        .output()
        .unwrap_or_else(|e| panic!("run --explain BP-1: {e}"));
    let stdout = String::from_utf8_lossy(&run.stdout);

    assert!(run.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("BP-1"), "stdout:\n{stdout}");
    assert!(stdout.contains("Discarded Error Return"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("A returned error is assigned to `_`, suppressing error handling."),
        "stdout:\n{stdout}"
    );
}

#[test]
fn json_finding_includes_bad_practice_category() {
    let finding = Finding::new(FindingInputs::new(
        "BP-1",
        "Discarded Error Return",
        "bad.go",
        LineCol { line: 3, column: 2 },
        "discarded error",
        Severity::Low,
        Cow::Borrowed(&[]),
    ));
    let value = serde_json::to_value(FindingJson::from(&finding)).unwrap();

    assert_eq!(value["category"], "bad_practice");
}

#[test]
fn sarif_bad_practice_results_have_category_and_medium_security_severity() {
    let result = AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(FindingInputs::new(
            "BP-1",
            "Discarded Error Return",
            "bad.go",
            LineCol { line: 3, column: 2 },
            "discarded error",
            Severity::Low,
            Cow::Borrowed(&[]),
        ))],
        errors: vec![],
        suppressed_count: 0,
        stats: None,
    };

    let log = render_to_string(&result).expect("render SARIF");

    assert!(log.contains("\"category\": \"bad_practice\""), "got: {log}");
    assert!(log.contains("\"security-severity\": \"5.0\""), "got: {log}");
    assert!(log.contains("\"bad_practice\""), "got: {log}");
}
