//! Scan configuration: rule filters and exit policy.

mod context;
mod policy;

pub use context::ScanContext;
pub use policy::FailPolicy;
// Profile lives in `core::profile` (re-exported from `core`).
