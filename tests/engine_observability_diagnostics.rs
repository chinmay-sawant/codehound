use std::borrow::Cow;

use slopguard::engine::{Diagnostics, ScanStats};
use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

fn sample_result_with_stats() -> slopguard::engine::AnalysisResult {
    slopguard::engine::AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        ))],
        errors: vec![],
        suppressed_count: 0,
        stats: Some(ScanStats {
            files_scanned: 3,
            files_skipped: 1,
            files_errored: 0,
            bytes_scanned: 1234,
            lines_scanned: 42,
            cache_hits: 0,
            cache_misses: 0,
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

    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/baseline/suppressed_inline.txt");

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--",
            "--diagnostics",
            diagnostics_path.to_str().unwrap(),
            source_path.to_str().unwrap(),
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
