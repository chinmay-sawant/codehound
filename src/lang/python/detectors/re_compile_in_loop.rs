//! SLOP101: re.compile inside loop (Python).

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::CWE_REFS_400_1336;
use crate::lang::python::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::python::matchers::is_re_compile_call;
use crate::rules::{emit, Finding, Rule, RuleMetadata, Severity};

pub struct ReCompileInLoop;

impl Rule for ReCompileInLoop {
    fn metadata(&self) -> RuleMetadata {
        emit::rule_meta(
            "SLOP101",
            "re.compile called inside loop",
            "Compiling a regex on every iteration is wasteful; compile once outside the loop.",
            Severity::Warning,
            CWE_REFS_400_1336,
            Some("Hoist `re.compile(...)` before the loop or use a module-level pattern."),
        )
    }
}

impl Detector for ReCompileInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Python
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        &["SLOP101"]
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let file = unit.path.display().to_string();
        let src = unit.source.as_ref();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_re_compile_call(call, src.as_bytes()) {
                return;
            }
            if nearest_loop(call, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(call.start_byte());
            emit::push_finding_with_snippet(
                &self.metadata(),
                &file,
                line,
                col,
                "re.compile called inside loop body",
                snippet_of(src, call),
                out,
            );
        });
    }
}
