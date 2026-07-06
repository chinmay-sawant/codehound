//! Shared phase aggregation for timing summaries.

use std::collections::HashMap;
use std::time::Duration;

use super::summary::PhaseTiming;

pub(super) fn aggregate_phases(
    by_name: HashMap<&'static str, (Duration, usize)>,
) -> (Duration, Vec<PhaseTiming>) {
    let total = by_name
        .values()
        .map(|(duration, _)| *duration)
        .fold(Duration::ZERO, |a, b| a + b);

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
    phases.sort_by_key(|b| std::cmp::Reverse(b.duration));

    (total, phases)
}
