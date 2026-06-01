//! Single-pass Go analysis — all loop detectors in one AST walk.

use crate::ast::{nearest_loop, snippet_of, walk_nodes};
use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::cwe::helpers::{CWE_REFS_400_1336, CWE_REFS_407, CWE_REFS_770, CWE_REFS_770_400};
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::lang::go::matchers::{
    is_append_call, is_make_map_call, is_regexp_compile, is_string_concat_assign,
};
use crate::rules::{emit, Finding, Rule, RuleMetadata, Severity};

pub const GO_RULE_IDS: &[&str] = &["SLOP001", "SLOP002", "SLOP003", "SLOP004"];

const META_SLOP001: RuleMetadata = emit::rule_meta(
    "SLOP001",
    "regexp.MustCompile called inside loop",
    "Compiling a regular expression on every loop iteration \
        is wasteful; compile once and reuse.",
    Severity::Warning,
    CWE_REFS_400_1336,
    Some("Move `regexp.MustCompile` out of the loop, e.g. as a package-level var."),
);

const META_SLOP002: RuleMetadata = emit::rule_meta(
    "SLOP002",
    "String concatenation inside loop",
    "Concatenating strings with `+` inside a hot loop is O(n^2). \
        Use a `strings.Builder`.",
    Severity::Warning,
    CWE_REFS_407,
    Some("Use `strings.Builder` (or `strings.Join`) and build once."),
);

const META_SLOP003: RuleMetadata = emit::rule_meta(
    "SLOP003",
    "Slice rebuilt with append inside loop",
    "Re-declaring a slice with `append` per iteration can \
        leak capacity and reallocate. Pre-size with `make([]T, 0, n)`.",
    Severity::Warning,
    CWE_REFS_770,
    Some("Allocate once with `make([]T, 0, expectedLen)` outside the loop."),
);

const META_SLOP004: RuleMetadata = emit::rule_meta(
    "SLOP004",
    "Map allocation inside loop",
    "Calling `make(map[..]..)` inside a loop allocates a new \
        map on every iteration. Reuse or hoist it out of the hot path.",
    Severity::Warning,
    CWE_REFS_770_400,
    Some("Hoist `make(map[..]..)` outside the loop or use `clear(m)`."),
);

/// Runs all enabled Go loop detectors in a single AST traversal.
pub fn analyze_unit(ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let check_s001 = ctx.allows("SLOP001");
    let check_s002 = ctx.allows("SLOP002");
    let check_s003 = ctx.allows("SLOP003");
    let check_s004 = ctx.allows("SLOP004");

    if !(check_s001 || check_s002 || check_s003 || check_s004) {
        return;
    }

    walk_nodes(root, &["call_expression", "assignment_statement", "short_var_declaration"], &mut |node| {
        match node.kind() {
            "call_expression" if check_s001 || check_s003 || check_s004 => {
                if check_s001
                    && is_regexp_compile(node, src)
                    && nearest_loop(node, LOOP_NODE_KINDS).is_some()
                {
                    let (line, col) = unit.line_col(node.start_byte());
                    emit::push_finding_with_snippet(
                        &META_SLOP001,
                        &file,
                        line,
                        col,
                        "regexp.MustCompile / regexp.Compile called inside loop body",
                        snippet_of(unit.source.as_ref(), node),
                        out,
                    );
                }
                if check_s003
                    && is_append_call(node, src)
                    && nearest_loop(node, LOOP_NODE_KINDS).is_some()
                {
                    let (line, col) = unit.line_col(node.start_byte());
                    emit::push_finding(
                        &META_SLOP003,
                        &file,
                        line,
                        col,
                        "append inside loop — pre-size the slice if length is known",
                        out,
                    );
                }
                if check_s004
                    && is_make_map_call(node, src)
                    && nearest_loop(node, LOOP_NODE_KINDS).is_some()
                {
                    let (line, col) = unit.line_col(node.start_byte());
                    emit::push_finding(
                        &META_SLOP004,
                        &file,
                        line,
                        col,
                        "map allocated inside loop — hoist or use clear()",
                        out,
                    );
                }
            }
            "assignment_statement" | "short_var_declaration" if check_s002 => {
                if is_string_concat_assign(node, src)
                    && nearest_loop(node, LOOP_NODE_KINDS).is_some()
                {
                    let (line, col) = unit.line_col(node.start_byte());
                    emit::push_finding(
                        &META_SLOP002,
                        &file,
                        line,
                        col,
                        "string concatenation inside loop body — use strings.Builder",
                        out,
                    );
                }
            }
            _ => {}
        }
    });
}

/// Bundled Go detector registered in the plugin registry.
pub struct GoScan;

impl Rule for GoScan {
    fn metadata(&self) -> RuleMetadata {
        META_SLOP001
    }
}

impl crate::core::Detector for GoScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        GO_RULE_IDS
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        analyze_unit(ctx, unit, out);
    }
}
