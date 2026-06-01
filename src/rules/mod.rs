//! Rule metadata and the `Finding` value type.

pub mod emit;
mod finding;
mod rule;
mod severity;

pub use finding::Finding;
pub use rule::{Rule, RuleMetadata};
pub use severity::Severity;
