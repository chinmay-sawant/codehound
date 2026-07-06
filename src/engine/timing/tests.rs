#[cfg(test)]
mod t {
    use std::time::Duration;

    use super::super::collector::TimingCollector;

    #[test]
    fn disabled_collector_is_noop() {
        let mut collector = TimingCollector::new(false);
        let value = collector.measure("noop", || 42);
        assert_eq!(value, 42);
        assert!(collector.to_summary().phases.is_empty());
    }

    #[test]
    fn measure_records_span() {
        let mut collector = TimingCollector::new(true);
        collector.measure("work", || std::thread::sleep(Duration::from_millis(1)));
        let summary = collector.to_summary();
        assert_eq!(summary.phases.len(), 1);
        assert_eq!(summary.phases[0].name, "work");
        assert!(summary.phases[0].count >= 1);
    }

    #[test]
    fn merge_combines_spans() {
        let mut a = TimingCollector::new(true);
        let mut b = TimingCollector::new(true);
        a.measure("phase", || ());
        b.measure("phase", || ());
        a.merge(&b);
        let summary = a.to_summary();
        assert_eq!(summary.phases[0].count, 2);
    }

    #[test]
    fn with_timing_drains_global_collector() {
        use super::super::collector::with_timing;

        let (value, summary) = with_timing(|| {
            super::super::global_start("file_read");
            super::super::global_stop(0);
            7
        });

        assert_eq!(value, 7);
        let summary = summary.expect("timing summary");
        assert!(
            summary.phases.iter().any(|p| p.name == "file_read"),
            "expected file_read phase"
        );
    }

    #[cfg(feature = "go")]
    #[test]
    fn with_timing_captures_phases_during_analyze_paths() {
        use std::path::Path;

        use crate::core::ScanContext;
        use crate::engine::Analyzer;
        use crate::fixture::materialize_fixture;

        use super::super::collector::with_timing;

        let fixture = Path::new("tests/fixtures/go/baseline/suppressed_inline.txt");
        let source_path = materialize_fixture(fixture).expect("materialize fixture");
        let scan_root = source_path.parent().expect("fixture parent");

        let analyzer = Analyzer::builder()
            .scan_context(ScanContext {
                debug_timing: true,
                ..ScanContext::default()
            })
            .collect_stats(true)
            .build();

        let (result, global_summary) = with_timing(|| {
            analyzer
                .analyze_paths(&[scan_root], None)
                .expect("analyze_paths")
        });

        // `analyze_paths` drains the global collector into its local
        // `TimingCollector`, so `with_timing` sees an empty global here.
        assert!(global_summary.is_none());

        let stats = result.stats.expect("stats");
        let timing = stats.timing.expect("timing");
        assert!(
            timing.phases.iter().any(|p| {
                p.name == "file_read" || p.name == "tree_sitter_parse" || p.name == "file_walk"
            }),
            "unexpected phases: {:?}",
            timing.phases.iter().map(|p| p.name).collect::<Vec<_>>()
        );
    }
}
