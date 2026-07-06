//! Python language plugin (stub + first detector).

mod detectors;
mod register;

const LOOP_NODE_KINDS: &[&str] = &["for_statement", "while_statement"];

use crate::core::LanguageId;
use crate::lang::plugin::tree_sitter_lang;

tree_sitter_lang!(
    PythonLang,
    PythonPlugin,
    LanguageId::Python,
    tree_sitter_python::LANGUAGE.into(),
    "tree-sitter-python",
    &["py"],
    detectors::all(),
    &[],
    LOOP_NODE_KINDS
);
