//! SLOP001: regexp compile inside loop.

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::cwe_slice;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_regexp_compile;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

pub struct RegexpInLoop;

impl Rule for RegexpInLoop {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SLOP001",
            title: "regexp.MustCompile called inside loop",
            description: "Compiling a regular expression on every loop iteration \
                is wasteful; compile once and reuse.",
            severity: Severity::Warning,
            cwe: cwe_slice(&[400, 1336]),
            fix: Some("Move `regexp.MustCompile` out of the loop, e.g. as a package-level var."),
        }
    }
}

impl Detector for RegexpInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let src = unit.source.as_ref();
        let root = unit.tree.root_node();
        walk_calls(root, &mut |call| {
            if !is_regexp_compile(call, src.as_bytes()) {
                return;
            }
            if nearest_loop(call, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(call.start_byte());
            let meta = self.metadata();
            out.push(
                Finding::new(
                    meta.id,
                    meta.title,
                    unit.path.display().to_string(),
                    line,
                    col,
                    "regexp.MustCompile / regexp.Compile called inside loop body",
                    meta.severity,
                    meta.cwe.to_vec(),
                )
                .with_snippet(snippet_of(src, call))
                .with_fix(meta.fix.unwrap_or("")),
            );
        });
    }
}
