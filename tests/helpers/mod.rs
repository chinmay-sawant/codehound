//! Shared integration-test helpers.
//!
//! Each integration test binary only uses a subset of these helpers.
#![allow(dead_code)]

use std::path::Path;

use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_fixture, materialize_tree, materialized_root};

pub mod baseline;

/// Materialize a `.txt` fixture and verify it parses; does not run the analyzer.
pub fn assert_fixture_materializes(txt_path: &str) -> std::path::PathBuf {
    assert!(
        Path::new(txt_path).is_file(),
        "fixture missing (mandatory .txt): {txt_path}"
    );
    assert!(
        txt_path.ends_with(".txt"),
        "fixtures must use .txt text format, not source extensions: {txt_path}"
    );

    materialize_fixture(Path::new(txt_path))
        .unwrap_or_else(|e| panic!("materialize {txt_path}: {e:#}"))
}

/// Infer the rule class (`"CWE-"` or `"PERF-"`) from the fixture path so the
/// `required_rules == []` branch of `assert_fixture_rules` only enforces
/// silence on the class the test cares about.
fn infer_rule_class(txt_path: &str) -> &'static str {
    if txt_path.contains("/perf/") {
        "PERF-"
    } else if txt_path.contains("/bad_practices/") {
        "BP-"
    } else {
        "CWE-"
    }
}

/// Materialize a `.txt` fixture, analyze it, and assert required rules fired.
pub fn assert_fixture_rules(txt_path: &str, required_rules: &[&str]) {
    assert!(
        Path::new(txt_path).is_file(),
        "fixture missing (mandatory .txt): {txt_path}"
    );
    assert!(
        txt_path.ends_with(".txt"),
        "fixtures must use .txt text format, not source extensions: {txt_path}"
    );

    let source_path = assert_fixture_materializes(txt_path);

    let analyzer = Analyzer::builder().build();
    let result = analyzer
        .analyze_paths([&source_path], None)
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", source_path.display()));

    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    if required_rules.is_empty() {
        // `required_rules` is empty, so the caller is asserting that the
        // fixture is "clean" w.r.t. whatever rule class it cares about. The
        // CWE integration tests use this for safe fixtures and only care
        // that no CWE-* findings fire (PERF findings on a CWE-safe fixture
        // are valid signals, not test failures).
        let class = infer_rule_class(txt_path);
        let matching: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| id.starts_with(class))
            .collect();
        assert!(
            matching.is_empty(),
            "fixture {txt_path} → {}: expected no {class} findings, got {ids:?}",
            source_path.display()
        );
        return;
    }

    for rule in required_rules {
        assert!(
            ids.contains(rule),
            "fixture {txt_path} → {}: expected rule {rule}, got {ids:?}",
            source_path.display()
        );
    }
}

/// Like `assert_fixture_rules` but uses a custom `ScanContext`.
pub fn assert_fixture_rules_with_context(
    txt_path: &str,
    required_rules: &[&str],
    analyzer: &Analyzer,
) {
    assert!(
        Path::new(txt_path).is_file(),
        "fixture missing (mandatory .txt): {txt_path}"
    );
    assert!(
        txt_path.ends_with(".txt"),
        "fixtures must use .txt text format, not source extensions: {txt_path}"
    );

    let source_path = assert_fixture_materializes(txt_path);
    let result = analyzer
        .analyze_paths([&source_path], None)
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", source_path.display()));

    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    if required_rules.is_empty() {
        let class = infer_rule_class(txt_path);
        let matching: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| id.starts_with(class))
            .collect();
        assert!(
            matching.is_empty(),
            "fixture {txt_path} → {}: expected no {class} findings, got {ids:?}",
            source_path.display()
        );
        return;
    }

    for rule in required_rules {
        assert!(
            ids.contains(rule),
            "fixture {txt_path} → {}: expected rule {rule}, got {ids:?}",
            source_path.display()
        );
    }
}

/// Materialize all `*.{FIXTURE_EXTENSION}` under `fixtures_root`, then scan the generated tree.
pub fn assert_mixed_txt_fixtures(fixtures_root: &str, go_rules: &[&str], python_rules: &[&str]) {
    materialize_tree(Path::new(fixtures_root))
        .unwrap_or_else(|e| panic!("materialize_tree {fixtures_root}: {e:#}"));

    let analyzer = Analyzer::builder().build();
    let result = analyzer
        .analyze_paths([materialized_root()], None)
        .unwrap_or_else(|e| panic!("analyze materialized fixtures: {e:#}"));

    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();

    for rule in go_rules {
        assert!(
            ids.contains(rule),
            "mixed materialized scan: expected Go rule {rule}, got {ids:?}"
        );
    }
    for rule in python_rules {
        assert!(
            ids.contains(rule),
            "mixed materialized scan: expected Python rule {rule}, got {ids:?}"
        );
    }
}
