//! SLOP101: re.compile inside loop (Python).

use crate::ast::{nearest_loop, snippet_of, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::CWE_REFS_400_1336;
use crate::lang::python::LOOP_NODE_KINDS;
use crate::rules::{Finding, RuleMetadata, Severity, emit};

fn is_re_compile_call(node: tree_sitter::Node, src: &[u8]) -> bool {
    let Some(func) = node.child_by_field_name("function") else {
        return false;
    };
    let text = func.utf8_text(src).unwrap_or("");
    text == "re.compile" || text == "compile" || text.ends_with(".compile")
}

const SLOP101_META: RuleMetadata = RuleMetadata {
    id: "SLOP101",
    title: "re.compile called inside loop",
    description: "Compiling a regex on every iteration is wasteful; compile once outside the loop.",
    severity: Severity::Medium,
    cwe: CWE_REFS_400_1336,
    fix: Some("Hoist `re.compile(...)` before the loop or use a module-level pattern."),
};

pub struct ReCompileInLoop;

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
