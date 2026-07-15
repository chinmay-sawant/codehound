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
use crate::rules::{Finding, RuleMetadata};
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

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let facts = build_go_perf_facts(unit);
        for (rule_id, detector, _) in GO_PERF_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }
    }
}
