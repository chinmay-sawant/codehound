//! Go tree-sitter parser.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tree_sitter::Parser;

use crate::core::{LanguageId, ParsedUnit};

pub fn configure(parser: &mut Parser) {
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("tree-sitter-go grammar must load");
}

pub fn parse_with(
    parser: &mut Parser,
    path: &Path,
    source: Arc<str>,
) -> Result<ParsedUnit> {
    let tree = parser
        .parse(source.as_ref(), None)
        .ok_or_else(|| anyhow::anyhow!("tree-sitter failed to parse {}", path.display()))?;
    Ok(ParsedUnit {
        language: LanguageId::Go,
        path: path.to_path_buf(),
        source,
        tree,
    })
}
