//! Static CWE catalog (curated subset relevant to Go performance / slop).
//!
//! Last reviewed against <https://cwe.mitre.org/data/definitions/>.

use super::cwe::CweRef;

/// Curated CWE entries referenced by SlopGuard rules.
pub static CWE_CATALOG: &[CweRef] = &[
    CweRef::new(
        400,
        "Uncontrolled Resource Consumption",
        "https://cwe.mitre.org/data/definitions/400.html",
    ),
    CweRef::new(
        405,
        "Asymmetric Resource Consumption (Amplification)",
        "https://cwe.mitre.org/data/definitions/405.html",
    ),
    CweRef::new(
        407,
        "Algorithmic Complexity",
        "https://cwe.mitre.org/data/definitions/407.html",
    ),
    CweRef::new(
        770,
        "Allocation of Resources Without Limits or Throttling",
        "https://cwe.mitre.org/data/definitions/770.html",
    ),
    CweRef::new(
        1336,
        "Improper Neutralization of Special Elements Used in a Template Engine",
        "https://cwe.mitre.org/data/definitions/1336.html",
    ),
    CweRef::new(
        1041,
        "Use of Redundant Code",
        "https://cwe.mitre.org/data/definitions/1041.html",
    ),
];
