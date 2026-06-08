//! PERF-26 to PERF-050: general performance detectors grouped by thematic cluster.

mod allocations_and_reuse;
mod concurrency_and_path;
mod loops_and_iteration;

pub(crate) use allocations_and_reuse::*;
pub(crate) use concurrency_and_path::*;
pub(crate) use loops_and_iteration::*;
