//! SLOP101: re.compile inside loop (Python).

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::CWE_REFS_400_1336;
use crate::lang::python::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::python::matchers::is_re_compile_call;
use crate::rules::{Finding, Rule, RuleMetadata, Severity, emit};

const SLOP101_META: RuleMetadata = emit::rule_meta(
    "SLOP101",
    "re.compile called inside loop",
    "Compiling a regex on every iteration is wasteful; compile once outside the loop.",
    Severity::Medium,
    CWE_REFS_400_1336,
    Some("Hoist `re.compile(...)` before the loop or use a module-level pattern."),
);

pub struct ReCompileInLoop;

impl Rule for ReCompileInLoop {
    fn metadata(&self) -> RuleMetadata {
        SLOP101_META.clone()
    }
}

impl Detector for ReCompileInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Python
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        &["SLOP101"]
    }

    fn metadata_for(&self, rule_id: &str) -> Option<&'static RuleMetadata> {
        if rule_id == "SLOP101" {
            Some(&SLOP101_META)
        } else {
            None
        }
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let file = unit.display_path.as_str();
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
                &SLOP101_META,
                file,
                line,
                col,
                "re.compile called inside loop body",
                snippet_of(src, call),
                out,
            );
        });
    }
}
