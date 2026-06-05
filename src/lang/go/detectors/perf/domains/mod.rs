//! Domain-grouped Go PERF detector implementations.

mod loop_allocations;
mod parsing_in_loops;
mod request_path;

pub(crate) use loop_allocations::*;
pub(crate) use parsing_in_loops::*;
pub(crate) use request_path::*;
