//! Lightweight collector for named timing spans. Cloneable so per-worker
//! collectors can be merged back into a global collector after a parallel scan.

use std::time::{Duration, Instant};

use super::summary::TimingSummary;

#[derive(Debug, Clone)]
pub struct TimingSpan {
    pub name: &'static str,
    pub start: Instant,
    pub duration: Option<Duration>,
}

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

        let mut phases: Vec<super::summary::PhaseTiming> = by_name
            .into_iter()
            .map(|(name, (duration, count))| super::summary::PhaseTiming {
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
