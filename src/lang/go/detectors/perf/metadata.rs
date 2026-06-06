use crate::rules::{RuleMetadata, emit};

macro_rules! perf_ref_slice {
    ($num:literal, $title:literal) => {
        // PERF rules are performance heuristics, not CWE weaknesses. The metadata
        // intentionally carries an empty CWE reference slice so reports show
        // "n/a" in the CWE column without inventing a weak mapping.
        &[] as &'static [crate::cwe::CweRef]
    };
}

include!("metadata_overrides.rs");
include!(concat!(env!("OUT_DIR"), "/go_perf_metadata.rs"));
