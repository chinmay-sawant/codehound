//! SLOP003: append inside loop.

use crate::ast::{nearest_loop, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::cwe_slice;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_append_call;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

pub struct SliceRebuildInLoop;

impl Rule for SliceRebuildInLoop {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SLOP003",
            title: "Slice rebuilt with append inside loop",
            description: "Re-declaring a slice with `append` per iteration can \
                leak capacity and reallocate. Pre-size with `make([]T, 0, n)`.",
            severity: Severity::Warning,
            cwe: cwe_slice(&[770]),
            fix: Some("Allocate once with `make([]T, 0, expectedLen)` outside the loop."),
        }
    }
}

impl Detector for SliceRebuildInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let src = unit.source.as_bytes();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_append_call(call, src) || nearest_loop(call, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(call.start_byte());
            let meta = self.metadata();
            out.push(Finding::new(
                meta.id,
                meta.title,
                unit.path.display().to_string(),
                line,
                col,
                "append inside loop — pre-size the slice if length is known",
                meta.severity,
                meta.cwe.to_vec(),
            ));
        });
    }
}
