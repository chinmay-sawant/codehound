//! Go tree-sitter parser.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tree_sitter::Parser;

use crate::ast::compute_line_starts;
use crate::core::{LanguageId, ParsedUnit};

pub fn configure(parser: &mut Parser) {
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("tree-sitter-go grammar must load");
}

pub fn parse_with(parser: &mut Parser, path: &Path, source: Arc<str>) -> Result<ParsedUnit> {
    let tree = parser
        .parse(source.as_ref(), None)
        .ok_or_else(|| anyhow::anyhow!("tree-sitter failed to parse {}", path.display()))?;
    let line_starts = compute_line_starts(&source);
    Ok(ParsedUnit {
        language: LanguageId::Go,
        display_path: path.display().to_string(),
        path: path.to_path_buf(),
        source,
        tree,
        line_starts,
        function_spans: Vec::new(),
    })
}

/// Convenience helper for unit tests.
#[allow(dead_code)]
pub fn parse_go(source: &str) -> Result<ParsedUnit> {
    let mut parser = Parser::new();
    configure(&mut parser);
    parse_with(&mut parser, Path::new("sample.go"), Arc::from(source))
}
