//! Go performance heuristics.
//!
//! Mirrors the CWE bundle layout: one [`Detector`] implementation per language,
//! one typed `registry.toml` driving `build.rs`, and one module per domain under
//! `domains/`. CWE references for severity/fix overrides live in
//! The generated metadata uses the `metadata_overrides` module.

#[doc(hidden)]
pub mod common;
#[doc(hidden)]
pub mod domains;
#[doc(hidden)]
pub mod facts;
#[doc(hidden)]
pub mod source_index;
pub mod tiers;

mod metadata;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, RuleMetadata, RulePack, TimingGranularity};
use domains::*;
use facts::{GoPerfFacts, build_go_perf_facts};

type GoPerfRuleFn = fn(&ParsedUnit, &GoPerfFacts, &mut Vec<Finding>);
type GoPerfEntry = (&'static str, GoPerfRuleFn, &'static RuleMetadata);

include!(concat!(env!("OUT_DIR"), "/go_perf_registry.rs"));

pub struct GoPerfScan;

impl Detector for GoPerfScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        self::metadata::GO_PERF_RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<&'static RuleMetadata> {
        GO_PERF_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| *meta)
    }

    fn pack(&self) -> RulePack {
        RulePack::Performance
    }

    fn timing_granularity(&self) -> TimingGranularity {
        TimingGranularity::DetectorSpan
    }

    fn timing_label(&self) -> &'static str {
        "GoPerfScan"
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let needs_facts = GO_PERF_RULES
            .iter()
            .any(|(rule_id, _, _)| ctx.allows(rule_id) && rule_requires_facts(rule_id));
        let facts = if needs_facts {
            build_go_perf_facts(unit)
        } else {
            Default::default()
        };
        for (rule_id, detector, _) in GO_PERF_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }
    }
}

/// Rules in this deliberately small set inspect only the parsed unit/source.
///
/// Keep the default conservative: every new rule pays for facts until its
/// implementation is demonstrated not to read them. This avoids coupling the
/// generated registry to detector implementation details while still keeping
/// narrow `--only` scans off the broad fact/index path.
fn rule_requires_facts(rule_id: &str) -> bool {
    !matches!(
        rule_id,
        "PERF-101"
            | "PERF-113"
            | "PERF-134"
            | "PERF-148"
            | "PERF-150"
            | "PERF-151"
            | "PERF-168"
            | "PERF-175"
            | "PERF-189"
            | "PERF-190"
            | "PERF-191"
            | "PERF-200"
            | "PERF-201"
            | "PERF-205"
            | "PERF-234"
            | "PERF-235"
            | "PERF-236"
            | "PERF-239"
            | "PERF-241"
    )
}

#[cfg(test)]
mod tests {
    use super::rule_requires_facts;

    #[test]
    fn source_only_rules_skip_broad_perf_facts() {
        assert!(!rule_requires_facts("PERF-134"));
        assert!(!rule_requires_facts("PERF-241"));
        assert!(rule_requires_facts("PERF-9"));
    }
}
