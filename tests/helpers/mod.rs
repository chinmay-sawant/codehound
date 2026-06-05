//! Shared integration-test helpers.
//!
//! Each integration test binary only uses a subset of these helpers.
#![allow(dead_code)]

use std::path::Path;

use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_fixture, materialize_tree, materialized_root};

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
        .analyze_paths([&source_path])
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", source_path.display()));

    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    if required_rules.is_empty() {
        let cwe_ids: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| id.starts_with("CWE-"))
            .collect();
        assert!(
            cwe_ids.is_empty(),
            "fixture {txt_path} → {}: expected no CWE findings, got {ids:?}",
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
        .analyze_paths([materialized_root()])
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
