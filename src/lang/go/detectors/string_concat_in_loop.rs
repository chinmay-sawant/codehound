//! SLOP002: string concat inside loop.

use crate::ast::{nearest_loop, walk_assignments};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::cwe_slice;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_string_concat_assign;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

pub struct StringConcatInLoop;

impl Rule for StringConcatInLoop {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SLOP002",
            title: "String concatenation inside loop",
            description: "Concatenating strings with `+` inside a hot loop is O(n^2). \
                Use a `strings.Builder`.",
            severity: Severity::Warning,
            cwe: cwe_slice(&[407]),
            fix: Some("Use `strings.Builder` (or `strings.Join`) and build once."),
        }
    }
}

impl Detector for StringConcatInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let src = unit.source.as_bytes();
        walk_assignments(unit.tree.root_node(), &mut |assign| {
            if !is_string_concat_assign(assign, src) {
                return;
            }
            if nearest_loop(assign, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(assign.start_byte());
            let meta = self.metadata();
            out.push(Finding::new(
                meta.id,
                meta.title,
                unit.path.display().to_string(),
                line,
                col,
                "string concatenation inside loop body — use strings.Builder",
                meta.severity,
                meta.cwe.to_vec(),
            ));
        });
    }
}
