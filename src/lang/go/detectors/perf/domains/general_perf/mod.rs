//! PERF-26 to PERF-127: general performance detectors grouped by
//! thematic cluster. The `stdlib_misuse` module holds the
//! Category-A pattern-match rules from the 101-127 batch.

mod allocations_and_reuse;
mod concurrency_and_path;
mod loops_and_iteration;
mod stdlib_misuse;

pub(crate) use allocations_and_reuse::*;
pub(crate) use concurrency_and_path::*;
pub(crate) use loops_and_iteration::*;
pub(crate) use stdlib_misuse::*;
