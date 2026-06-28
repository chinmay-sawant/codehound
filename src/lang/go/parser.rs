//! Go tree-sitter parser.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use tree_sitter::Parser;

use crate::Error;
use crate::ast::compute_line_starts;
use crate::core::{LanguageId, ParsedUnit};
use crate::lang::parser::{self, LangCache};

static GO_LANGUAGE: LangCache = OnceLock::new();

fn go_language() -> Result<&'static tree_sitter::Language, String> {
    parser::init_language(&GO_LANGUAGE, tree_sitter_go::LANGUAGE.into())
}

pub fn configure(parser: &mut Parser) -> Result<(), Error> {
    let lang = go_language().map_err(|e| Error::Grammar(e))?;
    parser
        .set_language(lang)
        .map_err(|e| Error::Grammar(format!("tree-sitter-go: {e}")))?;
    Ok(())
}

pub fn parse_with(parser: &mut Parser, path: &Path, source: Arc<str>) -> Result<ParsedUnit, Error> {
    let tree = parser
        .parse(source.as_ref(), None)
        .ok_or_else(|| Error::Parse {
            path: path.display().to_string(),
            detail: "tree-sitter returned None".to_string(),
        })?;
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

/// Convenience helper for detector unit tests.
#[cfg(test)]
pub fn parse_go(source: &str) -> Result<ParsedUnit, Error> {
    let mut parser = Parser::new();
    configure(&mut parser)?;
    parse_with(&mut parser, Path::new("sample.go"), Arc::from(source))
}
