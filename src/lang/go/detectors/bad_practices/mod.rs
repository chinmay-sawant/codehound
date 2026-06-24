//! Go bad-practice heuristics (P2.5 MVP).

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::CweRef;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

mod rules;

use rules::*;

type BadPracticeFn = fn(&ParsedUnit, &mut Vec<Finding>);
type BadPracticeEntry = (&'static str, BadPracticeFn, &'static RuleMetadata);

const BP_1_META: RuleMetadata = RuleMetadata {
    id: "BP-1",
    title: "Discarded Error Return",
    description: "A returned error is assigned to `_`, suppressing error handling.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("handle the error or explicitly ignore it with a comment"),
};

const BP_3_META: RuleMetadata = RuleMetadata {
    id: "BP-3",
    title: "Panic Outside Main Or Test",
    description: "panic is called outside main() or test files.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("return the error up the call stack instead of panicking"),
};

const BP_11_META: RuleMetadata = RuleMetadata {
    id: "BP-11",
    title: "Defer Inside Loop",
    description: "defer is used inside a loop body.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("move cleanup after the loop or use an explicit closure"),
};

const BAD_PRACTICE_RULES: &[BadPracticeEntry] = &[
    ("BP-1", detect_bp_1_discarded_error, &BP_1_META),
    ("BP-3", detect_bp_3_panic_outside_main, &BP_3_META),
    ("BP-11", detect_bp_11_defer_in_loop, &BP_11_META),
];

const RULE_IDS: &[&str] = &["BP-1", "BP-3", "BP-11"];

const SCAN_METADATA: RuleMetadata = RuleMetadata {
    id: "BP",
    title: "Go Bad Practices",
    description: "Common Go bad practices that hurt reliability or maintainability.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: None,
};

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
        RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<RuleMetadata> {
        BAD_PRACTICE_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| (*meta).clone())
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        for (rule_id, detector, _) in BAD_PRACTICE_RULES {
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
