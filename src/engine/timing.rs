//! Lightweight, optional timing infrastructure for scan phases and detectors.
//!
//! When disabled, the collector is a zero-cost no-op. When enabled, it records
//! named spans and can aggregate them into a per-run summary.

use std::time::{Duration, Instant};

use serde::Serialize;

/// A single timed span.
#[derive(Debug, Clone)]
pub struct TimingSpan {
    pub name: &'static str,
    pub start: Instant,
    pub duration: Option<Duration>,
}

/// Lightweight collector for named spans. Cloneable so per-worker collectors
/// can be merged back into a global collector after a parallel scan.
#[derive(Debug, Default, Clone)]
pub struct TimingCollector {
    spans: Vec<TimingSpan>,
    enabled: bool,
}

impl TimingCollector {
    pub fn new(enabled: bool) -> Self {
        Self {
            spans: Vec::new(),
            enabled,
        }
    }

    /// Returns true if this collector will actually record spans.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start a span and return its index. If disabled, returns 0 and does nothing.
    pub fn start(&mut self, name: &'static str) -> usize {
        if !self.enabled {
            return 0;
        }
        let idx = self.spans.len();
        self.spans.push(TimingSpan {
            name,
            start: Instant::now(),
            duration: None,
        });
        idx
    }

    /// Stop a span started with [`Self::start`]. If disabled, does nothing.
    pub fn stop(&mut self, index: usize) {
        if !self.enabled {
            return;
        }
        if let Some(span) = self.spans.get_mut(index) {
            span.duration = Some(span.start.elapsed());
        }
    }

    /// Time a closure and record its duration under the given name.
    pub fn measure<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T {
        if !self.enabled {
            return f();
        }
        let idx = self.start(name);
        let result = f();
        self.stop(idx);
        result
    }

    /// Merge another collector into this one. Spans remain in chronological
    /// order within each phase name; aggregation happens in [`Self::to_summary`].
    pub fn merge(&mut self, other: &Self) {
        if !self.enabled || !other.enabled {
            return;
        }
        self.spans.extend(other.spans.iter().cloned());
    }

    /// Aggregate spans by name and compute total wall time.
    pub fn to_summary(&self) -> TimingSummary {
        let mut by_name: std::collections::HashMap<&'static str, (Duration, usize)> =
            std::collections::HashMap::new();
        let mut total = Duration::ZERO;

        for span in &self.spans {
            let Some(duration) = span.duration else {
                continue;
            };
            let entry = by_name.entry(span.name).or_insert((Duration::ZERO, 0));
            entry.0 += duration;
            entry.1 += 1;
            total += duration;
        }

        let mut phases: Vec<PhaseTiming> = by_name
            .into_iter()
            .map(|(name, (duration, count))| PhaseTiming {
                name,
                duration,
                percentage: if total.is_zero() {
                    0.0
                } else {
                    duration.as_secs_f64() / total.as_secs_f64() * 100.0
                },
                count,
            })
            .collect();
        phases.sort_by(|a, b| b.duration.cmp(&a.duration));

        TimingSummary {
            total_wall_time: total,
            phases,
        }
    }
}

/// Human- and machine-readable summary of collected timings.
#[derive(Debug, Clone, Serialize)]
pub struct TimingSummary {
    #[serde(with = "duration_millis")]
    pub total_wall_time: Duration,
    pub phases: Vec<PhaseTiming>,
}

impl TimingSummary {
    /// Merge another summary into this one, recomputing totals and percentages.
    pub fn merge(&mut self, other: &TimingSummary) {
        let mut by_name: std::collections::HashMap<&'static str, (Duration, usize)> =
            std::collections::HashMap::new();
        for phase in &self.phases {
            by_name.insert(phase.name, (phase.duration, phase.count));
        }
        for phase in &other.phases {
            let entry = by_name.entry(phase.name).or_insert((Duration::ZERO, 0));
            entry.0 += phase.duration;
            entry.1 += phase.count;
        }

        let mut phases: Vec<PhaseTiming> = by_name
            .into_iter()
            .map(|(name, (duration, count))| PhaseTiming {
                name,
                duration,
                percentage: 0.0,
                count,
            })
            .collect();
        let total = phases
            .iter()
            .map(|p| p.duration)
            .fold(Duration::ZERO, |a, b| a + b);
        for phase in &mut phases {
            phase.percentage = if total.is_zero() {
                0.0
            } else {
                phase.duration.as_secs_f64() / total.as_secs_f64() * 100.0
            };
        }
        phases.sort_by(|a, b| b.duration.cmp(&a.duration));

        self.total_wall_time = total;
        self.phases = phases;
    }
}

/// Timing data for one named phase.
#[derive(Debug, Clone, Serialize)]
pub struct PhaseTiming {
    pub name: &'static str,
    #[serde(with = "duration_millis")]
    pub duration: Duration,
    pub percentage: f64,
    pub count: usize,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(d.as_secs_f64() * 1000.0)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let millis = f64::deserialize(d)?;
        Ok(Duration::from_secs_f64(millis / 1000.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
