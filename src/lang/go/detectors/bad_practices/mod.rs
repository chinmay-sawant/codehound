//! Go bad-practice heuristics (P2.5 MVP).

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, RuleMetadata};

mod common;
mod dispatch;
mod metadata;
mod rules;
mod source_index;

pub(crate) use metadata::*;

pub struct GoBadPracticeScan;

impl Detector for GoBadPracticeScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        dispatch::rule_ids()
    }

    fn metadata_for(&self, rule_id: &str) -> Option<&'static RuleMetadata> {
        metadata::metadata_for(rule_id)
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let index = source_index::SourceIndex::build(source_index::NEEDLES, unit.source.as_ref());
        let time_rules = ctx.debug_timing && crate::engine::active_enabled();
        for (rule_id, detector) in dispatch::BAD_PRACTICE_RULES {
            if !ctx.allows(rule_id) {
                continue;
            }
            let start = out.len();
            if time_rules {
                crate::engine::measure_active(rule_id, || {
                    detector(unit, &index, out);
                });
            } else {
                detector(unit, &index, out);
            }
            for finding in &mut out[start..] {
                ctx.apply_finding_overrides(finding);
            }
        }
    }
}
