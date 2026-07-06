//! Go language plugin.

pub mod detectors;

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
    LOOP_NODE_KINDS
);
