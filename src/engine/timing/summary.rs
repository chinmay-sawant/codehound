//! Human- and machine-readable summary of collected timings.

use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TimingSummary {
    #[serde(with = "super::millis::duration_millis")]
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
        phases.sort_by_key(|b| std::cmp::Reverse(b.duration));

        self.total_wall_time = total;
        self.phases = phases;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PhaseTiming {
    pub name: &'static str,
    #[serde(with = "super::millis::duration_millis")]
    pub duration: Duration,
    pub percentage: f64,
    pub count: usize,
}
