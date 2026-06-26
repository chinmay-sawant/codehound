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
}
