//! SLOP002: string concat inside loop.

use crate::ast::{nearest_loop, walk_assignments};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::CWE_REFS_407;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_string_concat_assign;
use crate::rules::{emit, Finding, Rule, RuleMetadata, Severity};

#[allow(dead_code)]
pub struct StringConcatInLoop;

impl Rule for StringConcatInLoop {
    fn metadata(&self) -> RuleMetadata {
        emit::rule_meta(
            "SLOP002",
            "String concatenation inside loop",
            "Concatenating strings with `+` inside a hot loop is O(n^2). \
                Use a `strings.Builder`.",
            Severity::Warning,
            CWE_REFS_407,
            Some("Use `strings.Builder` (or `strings.Join`) and build once."),
        )
    }
}

impl Detector for StringConcatInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        &["SLOP002"]
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let file = unit.path.display().to_string();
        let src = unit.source.as_bytes();
        walk_assignments(unit.tree.root_node(), &mut |assign| {
            if !is_string_concat_assign(assign, src) {
                return;
            }
            if nearest_loop(assign, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(assign.start_byte());
            emit::push_finding(
                &self.metadata(),
                &file,
                line,
                col,
                "string concatenation inside loop body — use strings.Builder",
                out,
            );
        });
    }
}
