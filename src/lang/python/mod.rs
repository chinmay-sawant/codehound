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
    LOOP_NODE_KINDS,
    |unit: &crate::core::ParsedUnit,
     project_root: &std::path::Path,
     _module_prefix: Option<&str>| {
        let mut out = Vec::new();
        crate::engine::dependencies::python_imports::extract(
            &unit.tree.root_node(),
            &unit.source,
            project_root,
            &unit.display_path,
            &mut out,
        );
        out
    }
);
