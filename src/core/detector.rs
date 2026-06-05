//! Detector trait — language-scoped analysis rule.

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, Rule};

/// Walks one parsed unit and appends findings.
pub trait Detector: Rule + Send + Sync {
    fn language(&self) -> LanguageId;

    /// Rule ids implemented by this detector (one id, or all ids in a language bundle).
    fn rule_ids(&self) -> &'static [&'static str];

    /// Rule metadata for a specific rule id when a detector implements many
    /// rules behind one execution unit.
    fn metadata_for(&self, rule_id: &str) -> Option<crate::rules::RuleMetadata> {
        if self.rule_ids().contains(&rule_id) {
            Some(self.metadata())
        } else {
            None
        }
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>);
}
