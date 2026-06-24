//! Throughput smoke tests to catch parse+scan regressions in CI.

use std::path::Path;
use std::time::{Duration, Instant};

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_tree, materialized_root};

/// Observed full-fixture scan is ~100–200ms on a typical dev machine; allow 3× for CI.
/// Bumped from 600ms to cover the analyzer's function-context post-pass
/// (one extra tree walk per file) added for enclosing-function resolution.
const MAX_FULL_SCAN: Duration = Duration::from_millis(900);

/// Collect + scan should stay well under the full-scan ceiling. Bumped from
/// 500ms to cover the function-context post-pass added for enclosing-function
/// resolution.
const MAX_COLLECT_AND_SCAN: Duration = Duration::from_millis(800);

#[test]
fn materialized_fixture_scan_within_smoke_budget() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    let start = Instant::now();
    let result = analyzer
        .analyze_paths([&root], None)
        .expect("scan materialized fixtures");
    let elapsed = start.elapsed();

    assert!(
        !result.findings.is_empty(),
        "smoke scan should produce findings on fixtures"
    );
    assert!(
        elapsed < MAX_FULL_SCAN,
        "parse+scan regression: took {:?} (limit {:?})",
        elapsed,
        MAX_FULL_SCAN
    );
}

#[test]
fn materialized_fixture_scan_repeat_within_budget() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    let mut worst = Duration::ZERO;
    for _ in 0..3 {
        let start = Instant::now();
        let result = analyzer
            .analyze_paths([&root], None)
            .expect("repeat scan materialized fixtures");
        assert!(!result.findings.is_empty());
        worst = worst.max(start.elapsed());
    }

    assert!(
        worst < MAX_COLLECT_AND_SCAN,
        "repeat scan regression: worst of 3 took {:?} (limit {:?})",
        worst,
        MAX_COLLECT_AND_SCAN
    );
}
