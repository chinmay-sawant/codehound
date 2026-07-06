//! Lightweight, optional timing infrastructure for scan phases and detectors.
//!
//! When disabled, the collector is a zero-cost no-op. When enabled, it records
//! named spans and can aggregate them into a per-run summary.
//!
//! Per-file / per-detector timing uses a global collector so the
//! [`TimingCollector`] does not appear in pipeline structs and function
//! signatures. App-level and analyzer-level timing still use locally-owned
//! [`TimingCollector`] instances.

mod collector;
mod millis;
mod summary;
#[cfg(test)]
mod tests;

pub use collector::{TimingCollector, TimingSpan};
pub(crate) use collector::{drain_global, global_start, global_stop, init_global};
pub use summary::{PhaseTiming, TimingSummary};

#[cfg(test)]
#[allow(unused_imports)]
pub use collector::with_timing;
