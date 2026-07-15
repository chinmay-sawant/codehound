#![warn(missing_docs)]

//! Rule metadata and the `Finding` value type.

pub mod emit;
mod evidence;
mod finding;
pub(crate) mod finding_view;
pub(crate) mod finding_wire;
pub mod maturity;
mod severity;

pub use emit::{push_finding, push_finding_with_evidence, push_finding_with_snippet, rule_meta};
pub use evidence::{ControlFlowKind, DetectorEvidence, TaintHop, TaintSinkInfo, TaintSourceInfo};
pub use finding::{Finding, FindingInputs, LineCol};
pub use finding_view::FindingView;
pub use maturity::{RuleMaturity, is_quarantined_from_default_packs, maturity_for};
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

/// Domain tag appended to the base SARIF tag set for a rule family.
pub fn sarif_family_tag_for_rule_id(rule_id: &str) -> Option<&'static str> {
    match category_for_rule_id(rule_id) {
        "security" => Some("cwe"),
        "performance" => Some("performance"),
        "bad_practice" => Some("bad_practice"),
        _ => None,
    }
}

/// Build SARIF `tags` for a finding using [`category_for_rule_id`] instead of
/// ad-hoc prefix checks at each reporter.
pub fn sarif_tags_for_finding(finding: &Finding) -> Vec<String> {
    FindingView::new(finding).sarif_tags()
}

/// Description of a detector / rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
