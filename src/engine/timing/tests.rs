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

    #[test]
    fn concurrent_timing_sessions_are_isolated() {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                std::thread::spawn(|| {
                    let (_, summary) = super::super::collector::with_timing(|| {
                        let span = super::super::global_start("file_read");
                        super::super::global_stop(span);
                    });
                    summary.expect("timing summary")
                })
            })
            .collect();

        for handle in handles {
            let summary = handle.join().expect("timing worker");
            assert_eq!(summary.phases[0].name, "file_read");
            assert_eq!(summary.phases[0].count, 1);
        }
    }

    #[test]
    fn global_collector_survives_multiple_chunk_drains() {
        use super::super::collector::{
            begin_global, drain_global, global_start, global_stop, reset_global,
        };

        let mut target = TimingCollector::new(true);
        let _guard = begin_global(true);
        let first = global_start("file_read");
        global_stop(first);
        drain_global(&mut target);

        let second = global_start("file_read");
        global_stop(second);
        drain_global(&mut target);

        let summary = target.to_summary();
        assert_eq!(summary.phases[0].name, "file_read");
        assert_eq!(summary.phases[0].count, 2);
        reset_global();
    }

    #[test]
    fn disabled_scan_does_not_clear_active_timing_session() {
        use super::super::collector::{begin_global, drain_global, global_start, global_stop};

        let mut target = TimingCollector::new(true);
        let _guard = begin_global(true);
        let first = global_start("file_read");
        global_stop(first);

        assert!(begin_global(false).is_none());

        drain_global(&mut target);
        assert_eq!(target.to_summary().phases[0].count, 1);
    }

    #[test]
    fn timing_session_drop_clears_global_after_unwind() {
        use super::super::collector::{begin_global, drain_global, global_start, global_stop};

        let result = std::panic::catch_unwind(|| {
            let _guard = begin_global(true);
            global_start("file_read");
            panic!("test unwind");
        });
        assert!(result.is_err());

        let mut target = TimingCollector::new(true);
        let _guard = begin_global(true);
        let span = global_start("file_read");
        global_stop(span);
        drain_global(&mut target);
        assert_eq!(target.to_summary().phases[0].count, 1);
    }

    #[cfg(feature = "go")]
    #[test]
    fn with_timing_captures_phases_during_analyze_paths() {
        use std::path::Path;

        use crate::core::ScanContext;
        use crate::engine::Analyzer;
        use crate::fixture::materialize_fixture;

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

        let result = analyzer
            .analyze_paths(&[scan_root], None)
            .expect("analyze_paths");

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

    #[cfg(feature = "go")]
    #[test]
    fn analyzer_builder_is_the_worker_timing_gate() {
        use std::path::Path;

        use crate::core::ScanContext;
        use crate::engine::Analyzer;
        use crate::fixture::materialize_fixture;

        let fixture = Path::new("tests/fixtures/go/baseline/suppressed_inline.txt");
        let source_path = materialize_fixture(fixture).expect("materialize fixture");
        let scan_root = source_path.parent().expect("fixture parent");

        let context_only = Analyzer::builder()
            .scan_context(ScanContext {
                debug_timing: true,
                ..ScanContext::default()
            })
            .collect_stats(false)
            .build();
        let context_only_result = context_only
            .analyze_paths(&[scan_root], None)
            .expect("context-only scan");
        assert!(
            context_only_result
                .stats
                .expect("stats")
                .timing
                .expect("timing")
                .phases
                .is_empty()
        );

        let builder_only = Analyzer::builder().collect_stats(true).build();
        let builder_only_result = builder_only
            .analyze_paths(&[scan_root], None)
            .expect("builder-only scan");
        assert!(
            !builder_only_result
                .stats
                .expect("stats")
                .timing
                .expect("timing")
                .phases
                .is_empty()
        );
    }

    #[cfg(feature = "go")]
    #[test]
    fn concurrent_analyzer_timing_is_isolated() {
        use std::path::Path;

        use crate::engine::Analyzer;
        use crate::fixture::materialize_fixture;

        let fixture = Path::new("tests/fixtures/go/baseline/suppressed_inline.txt");
        let source_path = materialize_fixture(fixture).expect("materialize fixture");
        let scan_root = source_path.parent().expect("fixture parent");
        let timed_a = Analyzer::builder().collect_stats(true).build();
        let timed_b = Analyzer::builder().collect_stats(true).build();
        let untimed = Analyzer::builder().collect_stats(false).build();

        let (timed_a, timed_b, untimed) = std::thread::scope(|scope| {
            let timed_a = scope.spawn(|| {
                timed_a
                    .analyze_paths(&[scan_root], None)
                    .expect("timed analyzer A")
            });
            let timed_b = scope.spawn(|| {
                timed_b
                    .analyze_paths(&[scan_root], None)
                    .expect("timed analyzer B")
            });
            let untimed = scope.spawn(|| {
                untimed
                    .analyze_paths(&[scan_root], None)
                    .expect("untimed analyzer")
            });
            (
                timed_a.join().expect("timed analyzer A thread"),
                timed_b.join().expect("timed analyzer B thread"),
                untimed.join().expect("untimed analyzer thread"),
            )
        });

        for result in [timed_a, timed_b] {
            assert!(
                !result
                    .stats
                    .expect("stats")
                    .timing
                    .expect("timing")
                    .phases
                    .is_empty()
            );
        }
        assert!(
            untimed
                .stats
                .expect("stats")
                .timing
                .expect("timing")
                .phases
                .is_empty()
        );
    }
}
