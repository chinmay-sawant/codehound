//! Rule metadata and the `Finding` value type.

pub mod emit;
mod finding;
mod fingerprint;
mod rule;
mod severity;

pub use emit::{push_finding, push_finding_with_snippet, rule_meta};
pub use finding::{Finding, LineCol};
pub use fingerprint::{FINGERPRINT_TOOL, FINGERPRINT_VERSION, Fingerprint, FingerprintParseError};
pub use rule::{Rule, RuleMetadata};
pub use severity::Severity;
