//! Go bad-practice heuristics (P2.5 MVP).

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, RuleMetadata};

mod common;
mod dispatch;
mod metadata;
mod rules;
mod source_index;

pub(crate) use metadata::*;

/// Pre-warm project-level BP caches for `root` before parallel file work.
pub(crate) fn prewarm_project_cache(root: &std::path::Path) {
    common::prewarm_project_snapshot(root);
}

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

    fn reset_state(&self) {
        // Project facts (package docs, go.mod, imports, server anchors) are
        // memoized for one top-level scan only. Clear them at both scan
        // boundaries so a same-Analyzer rescan cannot observe stale snapshots.
        common::clear_project_snapshots();
        rules::clear_package_doc_snapshots();
        rules::clear_dependency_hygiene_caches();
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let index = source_index::SourceIndex::build(source_index::NEEDLES, unit.source.as_ref());
        let time_rules = ctx.debug_timing && crate::engine::active_enabled();
        let has_enabled_project_rule = dispatch::BAD_PRACTICE_RULES.iter().any(|(rule_id, _)| {
            ctx.allows(rule_id)
                && (dispatch::requires_project_anchor(rule_id)
                    || dispatch::requires_server_anchor(rule_id))
        });
        let is_project_anchor = has_enabled_project_rule
            && !common::is_materialized_fixture(unit)
            && common::is_project_anchor(unit);
        let is_server_anchor = has_enabled_project_rule
            && !common::is_materialized_fixture(unit)
            && common::is_server_anchor(unit);
        for (rule_id, detector) in dispatch::BAD_PRACTICE_RULES {
            if !ctx.allows(rule_id) {
                continue;
            }
            if dispatch::requires_project_anchor(rule_id) && !is_project_anchor {
                continue;
            }
            if dispatch::requires_server_anchor(rule_id) && !is_server_anchor {
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
