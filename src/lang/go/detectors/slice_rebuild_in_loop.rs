//! SLOP003: append inside loop.

use crate::ast::{nearest_loop, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::CWE_REFS_770;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_append_call;
use crate::rules::{Finding, Rule, RuleMetadata, Severity, emit};

#[allow(dead_code)]
pub struct SliceRebuildInLoop;

impl Rule for SliceRebuildInLoop {
    fn metadata(&self) -> RuleMetadata {
        emit::rule_meta(
            "SLOP003",
            "Slice rebuilt with append inside loop",
            "Re-declaring a slice with `append` per iteration can \
                leak capacity and reallocate. Pre-size with `make([]T, 0, n)`.",
            Severity::Warning,
            CWE_REFS_770,
            Some("Allocate once with `make([]T, 0, expectedLen)` outside the loop."),
        )
    }
}

impl Detector for SliceRebuildInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        &["SLOP003"]
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let file = unit.path.display().to_string();
        let src = unit.source.as_bytes();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_append_call(call, src) || nearest_loop(call, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(call.start_byte());
            emit::push_finding(
                &self.metadata(),
                &file,
                line,
                col,
                "append inside loop — pre-size the slice if length is known",
                out,
            );
        });
    }
}
