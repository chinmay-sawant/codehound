//! PERF-26 to PERF-050: catch-all "general performance" detectors.
//!
//! Each submodule owns a contiguous slice of the rule range. Splitting
//! keeps every file under the 400-line cap that the rest of the Go
//! detector bundle uses (mirrors `cwe/domains/general_security/`).

mod part_1;
mod part_2;
mod part_3;

pub(crate) use part_1::*;
pub(crate) use part_2::*;
pub(crate) use part_3::*;
