//! CWE (Common Weakness Enumeration) catalog: curated constants, the
//! auto-generated full catalog, and rich per-rule descriptions.

mod consts;
mod description;

pub use consts::{CWE_CATALOG, CWE_REFS_400_1336, CWE_REFS_407, CWE_REFS_770, CWE_REFS_770_400};
pub use description::{
    RuleDescription, builtin_rule_catalogue, default_ruleset_path, load_rule_descriptions,
};
