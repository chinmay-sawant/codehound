//! SLOP004: make(map) inside loop.

use crate::ast::{nearest_loop, walk_calls};
use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::cwe_slice;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::is_make_map_call;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

pub struct MapAllocInLoop;

impl Rule for MapAllocInLoop {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SLOP004",
            title: "Map allocation inside loop",
            description: "Calling `make(map[..]..)` inside a loop allocates a new \
                map on every iteration. Reuse or hoist it out of the hot path.",
            severity: Severity::Warning,
            cwe: cwe_slice(&[770, 400]),
            fix: Some("Hoist `make(map[..]..)` outside the loop or use `clear(m)`."),
        }
    }
}

impl Detector for MapAllocInLoop {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn run(&self, _ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let src = unit.source.as_bytes();
        walk_calls(unit.tree.root_node(), &mut |call| {
            if !is_make_map_call(call, src) || nearest_loop(call, LOOP_NODE_KINDS).is_none() {
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
                "map allocated inside loop — hoist or use clear()",
                meta.severity,
                meta.cwe.to_vec(),
            ));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ScanContext;
    use crate::lang::go::test_utils::parse_snippet;

    #[test]
    fn detects_make_map_inside_range_loop() {
        let src = r#"
package p
func f(rows []string) {
    for _, r := range rows {
        _ = make(map[string]int)
    }
}
"#;
        let unit = parse_snippet(src);
        let mut out = Vec::new();
        MapAllocInLoop.run(&ScanContext::default(), &unit, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "SLOP004");
    }

    #[test]
    fn ignores_make_map_outside_loop() {
        let src = "package p\nfunc f() { _ = make(map[string]int) }\n";
        let unit = parse_snippet(src);
        let mut out = Vec::new();
        MapAllocInLoop.run(&ScanContext::default(), &unit, &mut out);
        assert!(out.is_empty());
    }
}
