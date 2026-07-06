#![warn(missing_docs)]

//! Rule metadata and the `Finding` value type.

pub mod emit;
mod evidence;
mod finding;
pub(crate) mod finding_wire;
mod severity;

pub use emit::{push_finding, push_finding_with_evidence, push_finding_with_snippet, rule_meta};
pub use evidence::{ControlFlowKind, DetectorEvidence, TaintHop, TaintSinkInfo, TaintSourceInfo};
pub use finding::{Finding, FindingInputs, LineCol};
pub use severity::Severity;

use serde::Serialize;

use crate::cwe::CweRef;

/// Coarse rule category derived from the rule ID prefix.
pub fn category_for_rule_id(rule_id: &str) -> &'static str {
    if rule_id.starts_with("BP-") {
        "bad_practice"
    } else if rule_id.starts_with("PERF-") {
        "performance"
    } else if rule_id.starts_with("CWE-") {
        "security"
    } else {
        "general"
    }
}

/// Description of a detector / rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleMetadata {
    /// Stable identifier, e.g. `CWE-89`.
    pub id: &'static str,
    /// Short title.
    pub title: &'static str,
    /// Longer description.
    pub description: &'static str,
    /// Default severity.
    pub severity: Severity,
    /// CWE references (can be multiple).
    pub cwe: &'static [CweRef],
    /// Suggested fix or note.
    pub fix: Option<&'static str>,
}
