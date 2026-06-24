use std::borrow::Cow;

use clap::Parser;
use slopguard::cli::Cli;
use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, Diagnostics, ScanStats, TimingCollector};
use slopguard::rules::{Finding, LineCol, Severity};

fn sample_result_with_stats() -> slopguard::engine::AnalysisResult {
    slopguard::engine::AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        )],
        errors: vec![],
        suppressed_count: 0,
        stats: Some(ScanStats {
            files_scanned: 3,
            files_skipped: 1,
            files_errored: 0,
            bytes_scanned: 1234,
            lines_scanned: 42,
            findings_total: 1,
            findings_by_severity: [("high".to_string(), 1)].into_iter().collect(),
            findings_by_rule: vec![("CWE-89".to_string(), 1)],
            findings_suppressed: 0,
            rules_executed: 5,
            detectors_loaded: 2,
            timing: None,
        }),
    }
}

#[test]
fn analyzer_collects_stats_when_enabled() {
    let ctx = ScanContext {
        debug_timing: true,
        ..ScanContext::default()
    };
    let analyzer = Analyzer::builder()
        .scan_context(ctx)
        .collect_stats(true)
        .build();

    let result = analyzer.analyze_paths(["tests/fixtures"]).unwrap();

    assert!(
        result.stats.is_some(),
        "stats should be collected when enabled"
    );
    let stats = result.stats.unwrap();
    assert!(stats.files_scanned > 0);
    assert!(stats.timing.is_some());
    let timing = stats.timing.unwrap();
    assert!(!timing.phases.is_empty());
}

#[test]
fn analyzer_omits_stats_when_disabled() {
    let analyzer = Analyzer::builder().collect_stats(false).build();
    let result = analyzer.analyze_paths(["src"]).unwrap();
    assert!(result.stats.is_none());
}

#[test]
fn timing_collector_disabled_is_noop() {
    let mut collector = TimingCollector::new(false);
    let value = collector.measure("work", || 42);
    assert_eq!(value, 42);
    assert!(collector.to_summary().phases.is_empty());
}

#[test]
fn timing_summary_merges_correctly() {
    let mut a = TimingCollector::new(true);
    a.measure("phase", || {
        std::thread::sleep(std::time::Duration::from_millis(1))
    });
    let mut b = TimingCollector::new(true);
    b.measure("phase", || {
        std::thread::sleep(std::time::Duration::from_millis(1))
    });

    let mut summary_a = a.to_summary();
    let summary_b = b.to_summary();
    summary_a.merge(&summary_b);

    assert_eq!(summary_a.phases[0].count, 2);
}

#[test]
fn debug_timing_and_diagnostics_flags_parse() {
    let cli = Cli::parse_from([
        "slopguard",
        "--debug-timing",
        "--diagnostics",
        "diag.json",
        ".",
    ]);
    assert!(cli.debug_timing);
    assert_eq!(
        cli.diagnostics.as_deref(),
        Some(std::path::Path::new("diag.json"))
    );
}

#[test]
fn scan_context_collects_stats_when_debug_timing_set() {
    let ctx = ScanContext {
        debug_timing: true,
        ..ScanContext::default()
    };
    assert!(ctx.collect_stats());
    assert!(ctx.collect_detector_timing());
}

#[test]
fn scan_context_collects_stats_when_diagnostics_set() {
    let ctx = ScanContext {
        diagnostics: true,
        ..ScanContext::default()
    };
    assert!(ctx.collect_stats());
}

#[test]
fn scan_stats_from_result_populates_findings() {
    let result = sample_result_with_stats();
    let stats = ScanStats::from_result(&result);

    assert_eq!(stats.findings_total, 1);
    assert_eq!(stats.findings_by_severity.get("high"), Some(&1));
    assert_eq!(stats.findings_by_rule, vec![("CWE-89".to_string(), 1)]);
}

#[test]
fn diagnostics_from_stats_serializes_expected_keys() {
    let result = sample_result_with_stats();
    let stats = result.stats.unwrap();
    let diagnostics = Diagnostics::from_stats(&stats);
    let json = serde_json::to_value(&diagnostics).unwrap();

    assert_eq!(json["tool"], "slopguard");
    assert!(!json["version"].as_str().unwrap().is_empty());
    assert!(json["timestamp"].as_str().unwrap().contains('T'));
    assert_eq!(json["scan"]["files_scanned"], 3);
    assert_eq!(json["findings"]["total"], 1);
    assert_eq!(json["findings"]["high"], 1);
    assert_eq!(json["detectors"]["loaded"], 2);
    assert_eq!(json["detectors"]["executed"], 5);
}

#[test]
fn diagnostics_flag_writes_valid_json_file() {
    let temp_dir =
        std::env::temp_dir().join(format!("slopguard-diagnostics-test-{}", std::process::id()));
    let diagnostics_path = temp_dir.join("diag.json");
    std::fs::create_dir_all(&temp_dir).unwrap();

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "--diagnostics",
            diagnostics_path.to_str().unwrap(),
            "tests/fixtures/go/baseline/suppressed_inline.go",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo run failed; ensure the binary builds");

    assert!(
        output.status.success(),
        "cargo run exited with {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&diagnostics_path)
        .unwrap_or_else(|e| panic!("diagnostics file not written: {e}"));
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(value["tool"], "slopguard");
    assert!(value["scan"]["files_scanned"].as_u64().unwrap_or(0) > 0);
    assert!(value["findings"]["total"].as_u64().is_some());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
