//! Static CWE catalog (curated subset relevant to Go performance / slop).
//!
//! Last reviewed against <https://cwe.mitre.org/data/definitions/>.

use crate::cwe::CweRef;

pub const CWE_400: CweRef = CweRef::new(
    400,
    "Uncontrolled Resource Consumption",
    "https://cwe.mitre.org/data/definitions/400.html",
);

#[allow(dead_code)]
pub const CWE_405: CweRef = CweRef::new(
    405,
    "Asymmetric Resource Consumption (Amplification)",
    "https://cwe.mitre.org/data/definitions/405.html",
);

pub const CWE_407: CweRef = CweRef::new(
    407,
    "Algorithmic Complexity",
    "https://cwe.mitre.org/data/definitions/407.html",
);

pub const CWE_770: CweRef = CweRef::new(
    770,
    "Allocation of Resources Without Limits or Throttling",
    "https://cwe.mitre.org/data/definitions/770.html",
);

pub const CWE_1336: CweRef = CweRef::new(
    1336,
    "Improper Neutralization of Special Elements Used in a Template Engine",
    "https://cwe.mitre.org/data/definitions/1336.html",
);

#[allow(dead_code)]
pub const CWE_1041: CweRef = CweRef::new(
    1041,
    "Use of Redundant Code",
    "https://cwe.mitre.org/data/definitions/1041.html",
);

// -- auto-generated entries from golang.json follow --
include!(concat!(env!("OUT_DIR"), "/cwe_catalog_generated.rs"));

/// Curated CWE entries referenced by SlopGuard rules.
pub static CWE_CATALOG: &[CweRef] = CWE_CATALOG_GENERATED;

/// Precomposed slices for rule metadata (no runtime allocation).
pub static CWE_REFS_400_1336: &[CweRef] = &[CWE_400, CWE_1336];
pub static CWE_REFS_407: &[CweRef] = &[CWE_407];
pub static CWE_REFS_770: &[CweRef] = &[CWE_770];
pub static CWE_REFS_770_400: &[CweRef] = &[CWE_770, CWE_400];
