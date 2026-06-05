//! Rule metadata and the `Finding` value type.

pub mod emit;
mod finding;
mod rule;
mod severity;

pub use emit::{push_finding, push_finding_with_snippet, rule_meta};
pub use finding::{Finding, LineCol};
pub use rule::{Rule, RuleMetadata};
pub use severity::Severity;
