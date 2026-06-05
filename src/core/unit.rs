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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parsed(source: &str) -> ParsedUnit {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("load go grammar");
        ParsedUnit {
            language: LanguageId::Go,
            display_path: String::from("test.go"),
            path: PathBuf::from("test.go"),
            source: Arc::from(source),
            tree: parser.parse(source, None).expect("parse"),
            line_starts: crate::ast::compute_line_starts(source),
        }
    }

    #[test]
    fn line_col_matches_underlying_ast_helper() {
        let source = "package main\nfunc main() {}\n";
        let unit = parsed(source);
        let offset = source.find("func").unwrap();
        assert_eq!(unit.line_col(offset), (2, 1));
        assert_eq!(unit.line_col(0), (1, 1));
    }

    #[test]
    fn line_col_for_offset_in_second_line() {
        let source = "package main\n    foo\n";
        let unit = parsed(source);
        let offset = source.find("foo").unwrap();
        assert_eq!(unit.line_col(offset), (2, 5));
    }

    #[test]
    fn line_col_for_offset_past_end_returns_last_line() {
        let source = "a\nb\nc\n";
        let unit = parsed(source);
        let offset = source.len() + 100;
        // Past end → clamp to last line known.
        let (line, _) = unit.line_col(offset);
        assert!(line >= 1, "got {line}");
    }
}
