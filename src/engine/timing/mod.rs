//! Lightweight, optional timing infrastructure for scan phases and detectors.
//!
//! When disabled, the collector is a zero-cost no-op. When enabled, it records
//! named spans and can aggregate them into a per-run summary.

mod collector;
mod millis;
mod summary;
#[cfg(test)]
mod tests;

pub use collector::{TimingCollector, TimingSpan};
pub use summary::{PhaseTiming, TimingSummary};
