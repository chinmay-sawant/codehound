//! Go bad-practice heuristics (P2.5 MVP).

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, Rule, RuleMetadata};

mod metadata;
mod dispatch;
mod rules;

pub(crate) use metadata::*;

pub struct GoBadPracticeScan;

impl Rule for GoBadPracticeScan {
    fn metadata(&self) -> RuleMetadata {
        SCAN_METADATA.clone()
    }
}

impl Detector for GoBadPracticeScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        dispatch::RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<RuleMetadata> {
        dispatch::BAD_PRACTICE_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| (*meta).clone())
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        for (rule_id, detector, _) in dispatch::BAD_PRACTICE_RULES {
            if ctx.allows(rule_id) {
                let start = out.len();
                detector(unit, out);
                for finding in &mut out[start..] {
                    ctx.apply_finding_overrides(finding);
                }
            }
        }
    }
}
