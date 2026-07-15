//! Parsed source unit passed to detectors.

use std::path::PathBuf;
use std::sync::Arc;

use tree_sitter::Tree;

use super::LanguageId;
use crate::ast::{self, FunctionSpan};

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
    /// Precomputed function spans, populated by a single tree walk at parse
    /// time. When non-empty, `attach_function_context` skips its own walk.
    pub function_spans: Vec<FunctionSpan>,
}

impl ParsedUnit {
    /// Return the language selected for this source unit.
    pub fn language(&self) -> LanguageId {
        self.language
    }

    /// Return the source path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Return the cached display path used by findings and cache keys.
    pub fn display_path(&self) -> &str {
        &self.display_path
    }

    /// Return the shared source text.
    pub fn source(&self) -> &Arc<str> {
        &self.source
    }

    /// Return the parsed syntax tree.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Return precomputed line-start byte offsets.
    pub fn line_starts(&self) -> &[usize] {
        &self.line_starts
    }

    /// Return precomputed function spans.
    pub fn function_spans(&self) -> &[FunctionSpan] {
        &self.function_spans
    }

    /// Replace function spans during the parser/enrichment phase.
    pub(crate) fn set_function_spans(&mut self, spans: Vec<FunctionSpan>) {
        self.function_spans = spans;
    }

    /// Convert a byte offset into a one-indexed line and column.
    pub fn line_col(&self, byte_offset: usize) -> (usize, usize) {
        ast::line_col_with_starts(&self.line_starts, byte_offset)
    }
}
