//! Parsed source unit passed to detectors.

use std::path::PathBuf;
use std::sync::Arc;

use tree_sitter::Tree;

use super::LanguageId;
use crate::ast;

/// A single source file parsed for analysis.
#[derive(Debug, Clone)]
pub struct ParsedUnit {
    pub language: LanguageId,
    pub path: PathBuf,
    pub source: Arc<str>,
    pub tree: Tree,
}

impl ParsedUnit {
    pub fn line_col(&self, byte_offset: usize) -> (usize, usize) {
        ast::line_col(&self.tree, byte_offset)
    }
}
