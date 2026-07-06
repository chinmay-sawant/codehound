//! Domain-grouped Go PERF detector implementations.
//!
//! ## File split criteria
//!
//! Split a detector source file when **both** are true:
//!
//! 1. The file exceeds **500 lines**, and
//! 2. It contains **multiple independent detector groups** (e.g. handler limits
//!    vs IO/runtime), each callable without shared private state.
//!
//! Keep detectors in one file when they share helpers or a single traversal.
//! Revisit splits when adding a third language so the pattern stays consistent.

mod concurrency;
mod data_access;
mod general_perf;
mod gin_framework;
mod loop_allocations;
mod memory_gc;
mod parsing_in_loops;
mod protocols;
mod request_path;
mod stdlib_optimization;
mod string_bytes;

pub(crate) use concurrency::*;
pub(crate) use data_access::*;
pub(crate) use general_perf::*;
pub(crate) use gin_framework::*;
pub(crate) use loop_allocations::*;
pub(crate) use memory_gc::*;
pub(crate) use parsing_in_loops::*;
pub(crate) use protocols::*;
pub(crate) use request_path::*;
pub(crate) use stdlib_optimization::*;
pub(crate) use string_bytes::*;
