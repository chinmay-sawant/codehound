//! Stdlib optimization PERF detectors split by concern.
//!
//! Split criteria (see `perf/domains/mod.rs`): file >500 lines with multiple
//! independent detector groups → one submodule per group.

mod handler_limits;
mod io_and_runtime;

pub(crate) use handler_limits::*;
pub(crate) use io_and_runtime::*;
