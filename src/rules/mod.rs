#![warn(missing_docs)]

//! Rule metadata and the `Finding` value type.

pub(crate) mod emit;
mod evidence;
pub(crate) mod explain;
mod finding;
pub(crate) mod finding_view;
pub(crate) mod finding_wire;
pub(crate) mod maturity;
pub(crate) mod pack;
mod severity;

pub use emit::{push_finding, push_finding_with_evidence, push_finding_with_snippet, rule_meta};
pub use evidence::{ControlFlowKind, DetectorEvidence, TaintHop, TaintSinkInfo, TaintSourceInfo};
pub use explain::RuleExplainability;
pub use finding::{Finding, FindingInputs, LineCol};
pub use finding_view::FindingView;
pub use maturity::{RuleMaturity, is_quarantined_from_default_packs, maturity_for};
pub use pack::{
    PERF_TIER_A_RULES, PERF_TIER_S_RULES, RulePack, SECURITY_PACK_RULES, STYLE_PACK_PATTERNS,
    TAINT_CORE_CWE_RULES, TimingGranularity,
};
pub use severity::Severity;

use serde::Serialize;

use crate::cwe::CweRef;

/// Coarse rule category derived from pack metadata for `rule_id`.
pub fn category_for_rule_id(rule_id: &str) -> &'static str {
    RulePack::from_rule_id(rule_id).category_str()
}

/// Domain tag appended to the base SARIF tag set for a rule family.
pub fn sarif_family_tag_for_rule_id(rule_id: &str) -> Option<&'static str> {
    match RulePack::from_rule_id(rule_id) {
        RulePack::Security => Some("cwe"),
        RulePack::Performance => Some("performance"),
        RulePack::BadPractice => Some("bad_practice"),
        RulePack::General => None,
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
    /// Product pack this rule belongs to (BP / PERF / CWE / general).
    pub pack: RulePack,
}
