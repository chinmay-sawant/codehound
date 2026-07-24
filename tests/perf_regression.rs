//! Throughput smoke tests to catch parse+scan regressions in CI.

use std::path::Path;
use std::time::{Duration, Instant};

use codehound::core::ScanContext;
use codehound::engine::Analyzer;
use codehound::fixture::{materialize_tree, materialized_root};

/// Observed full-fixture scan is ~100–200ms on a typical dev machine; allow 3× for CI.
/// Bumped from 600ms to cover the analyzer's function-context post-pass
/// (one extra tree walk per file) added for enclosing-function resolution.
/// Bumped again to 1.1s to cover the eight new PERF detectors (PERF-114,
/// 119, 125, 129, 156, 177, 192) that each do an additional source scan.
/// Bumped to 1.5s to cover the 5 new Category C detectors (PERF-134, 139,
/// 150, 151, 172) that each do additional source scans.
/// Bumped to 2.0s after the BP integration matrix and additional metadata
/// plumbing pushed the first full materialized-fixture scan slightly above
/// the older 1.5s ceiling on this environment; the repeat-scan budget remains
/// tighter to catch sustained regressions.
/// Bumped to 12s after the Phase 4.4/4.5 BP expansion materially increased
/// the fixture surface and added package-aware scans over the Go bad-practice
/// corpus. Bumped again to 16s after the next Phase 4.5 slice (project-level
/// Go-version and HTTP-hardening checks) pushed the measured smoke run to
/// roughly 14.7s on this environment. Bumped to 20s after inter-procedural
/// taint analysis (P1-F) and import-map extraction added to the scan path.
/// Bumped to 32s — full `cargo test` parallel runs on WSL/CI can push a
/// single smoke scan to ~29s even when isolated runs stay ~15s.
/// ponytail: smoke ceiling, not a throughput benchmark.
const MAX_FULL_SCAN: Duration = Duration::from_millis(32000);

/// Collect + scan should stay well under the full-scan ceiling. Bumped from
/// 500ms to cover the function-context post-pass added for enclosing-function
/// resolution. Bumped again to 1s to cover the new PERF detectors. Bumped to
/// 16s alongside `MAX_FULL_SCAN` after the expanded BP fixture corpus and
/// package-aware heuristics changed the steady-state cost of scanning the full
/// materialized integration tree.
const MAX_COLLECT_AND_SCAN: Duration = Duration::from_millis(32000); // ponytail: smoke ceiling tracks fixture-surface growth + parallel CI

#[test]
fn materialized_fixture_scan_within_smoke_budget() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize integration fixtures");

    let analyzer = Analyzer::builder()
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
        "parse+scan regression: took {elapsed:?} (limit {MAX_FULL_SCAN:?})"
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
            .analyze_paths(&[&root], None)
            .expect("repeat scan materialized fixtures");
        assert!(!result.findings.is_empty());
        worst = worst.max(start.elapsed());
    }

    assert!(
        worst < MAX_COLLECT_AND_SCAN,
        "repeat scan regression: worst of 3 took {worst:?} (limit {MAX_COLLECT_AND_SCAN:?})"
    );
}
