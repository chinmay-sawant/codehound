#![warn(missing_docs)]

//! Rule metadata and the `Finding` value type.

mod category;
pub mod emit;
mod evidence;
mod finding;
pub(crate) mod finding_wire;
mod fingerprint;
mod rule;
mod severity;
pub use category::{BadPracticeCategory, category_for_rule_id};
pub use emit::{push_finding, push_finding_with_evidence, push_finding_with_snippet, rule_meta};
pub use evidence::{ControlFlowKind, DetectorEvidence, TaintHop, TaintSinkInfo, TaintSourceInfo};
pub use finding::{Finding, FindingInputs, LineCol};
pub use fingerprint::{FINGERPRINT_TOOL, FINGERPRINT_VERSION, Fingerprint};
pub use rule::{Rule, RuleMetadata};
pub use severity::Severity;
