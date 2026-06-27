use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, TimingCollector};

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn analyzer_collects_stats_when_enabled() {
    let ctx = ScanContext {
        debug_timing: true,
        ..ScanContext::default()
    };
    let analyzer = Analyzer::builder()
        .with_default_filter()
        .scan_context(ctx)
        .collect_stats(true)
        .build();

    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/baseline/suppressed_inline.txt");
    let scan_root = source_path.parent().unwrap();
    let result = analyzer.analyze_paths([scan_root], None).unwrap();

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
    let analyzer = Analyzer::builder()
        .with_default_filter()
        .collect_stats(false)
        .build();
    let result = analyzer.analyze_paths(["src"], None).unwrap();
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
