//! SLOP101: re.compile inside loop (Python).

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::cwe_slice;
use crate::lang::python::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::python::matchers::is_re_compile_call;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

pub struct ReCompileInLoop;

impl Rule for ReCompileInLoop {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SLOP101",
            title: "re.compile called inside loop",
            description: "Compiling a regex on every iteration is wasteful; compile once outside the loop.",
            severity: Severity::Warning,
            cwe: cwe_slice(&[400, 1336]),
            fix: Some("Hoist `re.compile(...)` before the loop or use a module-level pattern."),
        }
    }
}

impl Detector for ReCompileInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Python
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let src = unit.source.as_ref();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_re_compile_call(call, src.as_bytes()) {
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
                    "re.compile called inside loop body",
                    meta.severity,
                    meta.cwe.to_vec(),
                )
                .with_snippet(snippet_of(src, call))
                .with_fix(meta.fix.unwrap_or("")),
            );
        });
    }
}
