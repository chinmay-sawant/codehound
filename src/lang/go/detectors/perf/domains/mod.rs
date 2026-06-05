//! Domain-grouped Go PERF detector implementations.

mod data_access;
mod general_perf;
mod gin_framework;
mod loop_allocations;
mod parsing_in_loops;
mod protocols;
mod request_path;

pub(crate) use data_access::*;
pub(crate) use general_perf::*;
pub(crate) use gin_framework::*;
pub(crate) use loop_allocations::*;
pub(crate) use parsing_in_loops::*;
pub(crate) use protocols::*;
pub(crate) use request_path::*;
