//! Parsed source unit passed to detectors.

use std::path::PathBuf;
use std::sync::Arc;

use tree_sitter::Tree;

use super::LanguageId;
use crate::ast;

/// A single source file parsed for analysis.
#[derive(Debug)]
pub struct ParsedUnit {
    pub language: LanguageId,
    pub path: PathBuf,
    /// Cached `path.display().to_string()` — computed once at parse time so the
    /// ~175 detectors that emit a finding for this unit don't re-allocate it.
    pub display_path: String,
    pub source: Arc<str>,
    pub tree: Tree,
    /// Byte offsets of the first byte of each line (1-indexed lookup via
    /// binary search). Built once at parse time so `line_col` is O(log N)
    /// instead of `O(tree depth)` per call.
    pub line_starts: Vec<usize>,
}

impl ParsedUnit {
    pub fn line_col(&self, byte_offset: usize) -> (usize, usize) {
        ast::line_col_with_starts(&self.line_starts, byte_offset)
    }
}
