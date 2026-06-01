//! SLOP001: regexp compile inside loop.

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::CWE_REFS_400_1336;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_regexp_compile;
use crate::rules::{Finding, Rule, RuleMetadata, Severity, emit};

#[allow(dead_code)]
pub struct RegexpInLoop;

impl Rule for RegexpInLoop {
    fn metadata(&self) -> RuleMetadata {
        emit::rule_meta(
            "SLOP001",
            "regexp.MustCompile called inside loop",
            "Compiling a regular expression on every loop iteration \
                is wasteful; compile once and reuse.",
            Severity::Warning,
            CWE_REFS_400_1336,
            Some("Move `regexp.MustCompile` out of the loop, e.g. as a package-level var."),
        )
    }
}

impl Detector for RegexpInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        &["SLOP001"]
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let file = unit.path.display().to_string();
        let src = unit.source.as_ref();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_regexp_compile(call, src.as_bytes()) {
                return;
            }
            if nearest_loop(call, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(call.start_byte());
            let meta = self.metadata();
            emit::push_finding_with_snippet(
                &meta,
                &file,
                line,
                col,
                "regexp.MustCompile / regexp.Compile called inside loop body",
                snippet_of(src, call),
                out,
            );
        });
    }
}
