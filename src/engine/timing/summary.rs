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

        let (total, phases) = super::aggregate::aggregate_phases(by_name);

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
