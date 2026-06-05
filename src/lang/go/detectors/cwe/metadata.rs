use crate::rules::{RuleMetadata, Severity, emit};

macro_rules! go_cwe_ref_slice {
    ($num:literal, $title:literal) => {
        &[crate::cwe::CweRef::new(
            $num,
            $title,
            concat!(
                "https://cwe.mitre.org/data/definitions/",
                stringify!($num),
                ".html"
            ),
        )]
    };
}

include!("metadata_overrides.rs");
include!(concat!(env!("OUT_DIR"), "/go_cwe_metadata.rs"));
