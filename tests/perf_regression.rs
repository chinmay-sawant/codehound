//! Lightweight throughput smoke test to catch large parse+scan regressions in CI.

use std::path::Path;
use std::time::{Duration, Instant};

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::fixture::{materialize_tree, materialized_root};

/// Generous ceiling for CI variance; tighten when baselines are stable.
const MAX_SCAN_WALL_TIME: Duration = Duration::from_secs(15);

#[test]
fn materialized_fixture_scan_within_smoke_budget() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let root = materialized_root();

    let start = Instant::now();
    let result = analyzer
        .analyze_paths([&root])
        .expect("scan materialized fixtures");
    let elapsed = start.elapsed();

    assert!(
        !result.findings.is_empty(),
        "smoke scan should produce findings on fixtures"
    );
    assert!(
        elapsed < MAX_SCAN_WALL_TIME,
        "parse+scan regression: took {:?} (limit {:?})",
        elapsed,
        MAX_SCAN_WALL_TIME
    );
}
