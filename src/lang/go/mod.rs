//! Go language plugin.

#[doc(hidden)]
pub mod detectors;
mod register;
/// Perfect-hash sink tables used by Go CWE detectors and tests.
pub mod sinks;

const FUNCTION_NODE_KINDS: &[&str] = &["function_declaration", "method_declaration"];
const LOOP_NODE_KINDS: &[&str] = &["for_statement"];

pub(crate) const CALL_ASSIGN_NODE_KINDS: &[&str] = &[
    "call_expression",
    "call",
    "assignment_statement",
    "short_var_declaration",
    "defer_statement",
    "go_statement",
    "for_statement",
    "func_literal",
    "type_assertion_expression",
];

use crate::core::LanguageId;
use crate::lang::plugin::tree_sitter_lang;

tree_sitter_lang!(
    GoLang,
    GoPlugin,
    LanguageId::Go,
    tree_sitter_go::LANGUAGE.into(),
    "tree-sitter-go",
    &["go"],
    detectors::all(),
    FUNCTION_NODE_KINDS,
    LOOP_NODE_KINDS,
    |unit: &crate::core::ParsedUnit,
     project_root: &std::path::Path,
     module_prefix: Option<&str>| {
        let mut out = Vec::new();
        crate::engine::dependencies::go_imports::extract(
            &unit.tree.root_node(),
            &unit.source,
            project_root,
            module_prefix.unwrap_or(""),
            &mut out,
        );
        out
    },
    |ctx: &crate::core::ScanContext, project_roots: &[&std::path::Path]| {
        // Pack-local BP project snapshot prewarm so parallel workers share one
        // WalkDir + text scan for project-level rules (BP-47/50/54/55).
        // Skip when BP is disabled (recommended pack often has BP off).
        if !ctx.bad_practices_enabled {
            return;
        }
        for root in project_roots {
            detectors::bad_practices::prewarm_project_cache(root);
        }
    }
);
