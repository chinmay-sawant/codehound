//! Bundled Go CWE heuristics.

pub mod facts;

pub mod common;
mod detector_group_a;
mod detector_group_b;
mod detector_group_c;
mod metadata;

use self::detector_group_a::*;
use self::detector_group_b::*;
use self::detector_group_c::*;
use self::facts::{GoUnitFacts, build_go_unit_facts};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, Rule, RuleMetadata};

type GoRuleFn = fn(&ParsedUnit, &GoUnitFacts, &mut Vec<Finding>);
type GoRuleEntry = (&'static str, GoRuleFn, &'static RuleMetadata);

include!(concat!(env!("OUT_DIR"), "/go_cwe_registry.rs"));

pub struct GoCweScan;

impl Rule for GoCweScan {
    fn metadata(&self) -> RuleMetadata {
        GO_RULES
            .first()
            .map(|(_, _, meta)| (*meta).clone())
            .expect("GO_RULES must not be empty")
    }
}

impl Detector for GoCweScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        self::metadata::GO_CWE_RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<RuleMetadata> {
        GO_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| (*meta).clone())
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let facts = build_go_unit_facts(unit);
        for (rule_id, detector, _) in GO_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }
    }
}
