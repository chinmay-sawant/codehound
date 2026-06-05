//! CWE (Common Weakness Enumeration) catalog + helpers.
//!
//! References: <https://cwe.mitre.org/>

mod catalog;
pub mod helpers;
mod reference;

pub use catalog::{
    CWE_CATALOG, CWE_REFS_400_1336, CWE_REFS_407, CWE_REFS_770, CWE_REFS_770_400, RuleDescription,
    builtin_rule_catalogue, default_ruleset_path, load_rule_descriptions,
};
pub use reference::CweRef;

use std::fmt;

/// Look up a CWE by its numeric id (e.g. `400`).
pub fn lookup(id: u32) -> Option<&'static CweRef> {
    CWE_CATALOG.iter().find(|c| c.id == id)
}

/// Format a CWE as `CWE-400` for display.
pub fn format_cwe(id: u32) -> impl fmt::Display {
    struct W(u32);
    impl fmt::Display for W {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "CWE-{}", self.0)
        }
    }
    W(id)
}
