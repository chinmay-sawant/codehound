//! Rule metadata constants for Go bad-practice detectors.

use crate::rules::{RuleMetadata, Severity, emit};

macro_rules! bp_ref_slice {
    () => {
        &[] as &'static [crate::cwe::CweRef]
    };
}

include!("metadata_overrides.rs");
include!(concat!(env!("OUT_DIR"), "/go_bp_metadata.rs"));

pub(crate) const SCAN_METADATA: RuleMetadata = emit::rule_meta(
    "BP",
    "Go Bad Practices",
    "Common Go bad practices that hurt reliability or maintainability.",
    Severity::Low,
    bp_ref_slice!(),
    None,
);
