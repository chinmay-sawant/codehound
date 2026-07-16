//! Human- and machine-readable summary of collected timings.

use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
/// Aggregated wall-clock timing for scan phases.
pub struct TimingSummary {
    /// Total elapsed wall-clock time represented by this summary.
    #[serde(with = "super::millis::duration_millis")]
    pub total_wall_time: Duration,
    /// Per-phase timing records.
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
/// Timing and invocation count for one named scan phase.
pub struct PhaseTiming {
    /// Stable phase name.
    pub name: &'static str,
    /// Total elapsed duration for the phase.
    #[serde(with = "super::millis::duration_millis")]
    pub duration: Duration,
    /// Phase duration as a percentage of the total.
    pub percentage: f64,
    /// Number of observations merged into this phase.
    pub count: usize,
}
