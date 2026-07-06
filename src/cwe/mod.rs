//! CWE (Common Weakness Enumeration) catalog + helpers.
//!
//! References: <https://cwe.mitre.org/>

mod consts;
mod description;
mod reference;

pub use consts::{CWE_CATALOG, CWE_REFS_400_1336};
pub use description::{
    RuleDescription, builtin_rule_catalogue, default_ruleset_path, load_rule_descriptions,
};
pub use reference::{CweRef, format_cwe_list};