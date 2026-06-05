//! Go performance detectors.

pub mod cwe;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![Box::new(cwe::GoCweScan)]
}
