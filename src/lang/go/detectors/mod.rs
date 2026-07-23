//! Go detectors: bundled CWE heuristics, PERF performance heuristics, and bad practices.

pub mod bad_practices;
pub mod cwe;
pub mod perf;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![
        // Typed session first so begin_scan installs before prepare_project fill.
        Box::new(super::typed::GoTypedScan::new()),
        Box::new(cwe::GoCweScan::new()),
        Box::new(perf::GoPerfScan),
        Box::new(bad_practices::GoBadPracticeScan::new()),
    ]
}
