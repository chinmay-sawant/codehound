//! Go detectors: bundled CWE heuristics and PERF performance heuristics.

pub mod cwe;
pub mod perf;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![Box::new(cwe::GoCweScan), Box::new(perf::GoPerfScan)]
}
