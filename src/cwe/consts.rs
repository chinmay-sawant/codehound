//! Static CWE catalog (curated subset relevant to Go performance / slop).
//!
//! Last reviewed against <https://cwe.mitre.org/data/definitions/>.

use crate::cwe::CweRef;

pub const CWE_400: CweRef = CweRef::new(
    400,
    "Uncontrolled Resource Consumption",
    "https://cwe.mitre.org/data/definitions/400.html",
);

pub const CWE_1336: CweRef = CweRef::new(
    1336,
    "Improper Neutralization of Special Elements Used in a Template Engine",
    "https://cwe.mitre.org/data/definitions/1336.html",
);

// -- auto-generated entries from ruleset/golang/chunks/*.json follow --
include!(concat!(env!("OUT_DIR"), "/cwe_catalog_generated.rs"));

/// Curated CWE entries referenced by SlopGuard rules.
pub static CWE_CATALOG: &[CweRef] = CWE_CATALOG_GENERATED;

/// Precomposed slices for rule metadata (no runtime allocation).
pub static CWE_REFS_400_1336: &[CweRef] = &[CWE_400, CWE_1336];
