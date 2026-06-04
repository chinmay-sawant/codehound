//! Go performance detectors.

mod cwe;
mod map_alloc_in_loop;
mod regexp_in_loop;
mod slice_rebuild_in_loop;
mod string_concat_in_loop;

use crate::lang::go::detectors::cwe::GoCweScan;
use crate::lang::go::scan::GoScan;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![Box::new(GoScan), Box::new(GoCweScan)]
}
