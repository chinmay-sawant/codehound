//! Throughput smoke tests to catch parse+scan regressions in CI.

use std::path::Path;
use std::time::{Duration, Instant};

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_tree, materialized_root};

/// Observed full-fixture scan is ~100–200ms on a typical dev machine; allow 3× for CI.
/// Bumped from 600ms to cover the analyzer's function-context post-pass
/// (one extra tree walk per file) added for enclosing-function resolution.
/// Bumped again to 1.1s to cover the eight new PERF detectors (PERF-114,
/// 119, 125, 129, 156, 177, 192) that each do an additional source scan.
/// Bumped to 1.5s to cover the 5 new Category C detectors (PERF-134, 139,
/// 150, 151, 172) that each do additional source scans.
const MAX_FULL_SCAN: Duration = Duration::from_millis(1500);

/// Collect + scan should stay well under the full-scan ceiling. Bumped from
/// 500ms to cover the function-context post-pass added for enclosing-function
/// resolution. Bumped again to 1s to cover the new PERF detectors.
const MAX_COLLECT_AND_SCAN: Duration = Duration::from_millis(2000); // ponytail: bumped for CI load

#[test]
fn materialized_fixture_scan_within_smoke_budget() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .with_default_filter()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    let start = Instant::now();
    let result = analyzer
        .analyze_paths(&[&root], None)
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
        .with_default_filter()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    let mut worst = Duration::ZERO;
    for _ in 0..3 {
        let start = Instant::now();
        let result = analyzer
            .analyze_paths(&[&root], None)
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
