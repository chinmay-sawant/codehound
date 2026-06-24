//! Go detectors: bundled CWE heuristics, PERF performance heuristics, and bad practices.

pub mod bad_practices;
pub mod cwe;
pub mod facts;
pub mod perf;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![
        Box::new(cwe::GoCweScan),
        Box::new(perf::GoPerfScan),
        Box::new(bad_practices::GoBadPracticeScan),
    ]
}
