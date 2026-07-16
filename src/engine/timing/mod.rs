//! Lightweight, optional timing infrastructure for scan phases and detectors.
//!
//! When disabled, the collector is a zero-cost no-op. When enabled, it records
//! named spans and can aggregate them into a per-run summary.
//!
//! Production per-file / per-detector timing uses worker-local collectors
//! merged at scan boundaries. The legacy global helpers are test-only
//! compatibility coverage; app-level and analyzer-level timing use
//! locally-owned [`TimingCollector`] instances.

mod aggregate;
mod collector;
mod millis;
mod summary;
#[cfg(test)]
mod tests;

pub use collector::TimingCollector;
#[cfg(test)]
pub(crate) use collector::{global_start, global_stop};
pub use summary::{PhaseTiming, TimingSummary};

#[cfg(test)]
#[allow(unused_imports)]
pub use collector::with_timing;
