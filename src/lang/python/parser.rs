//! Python tree-sitter parser.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use tree_sitter::Parser;

use crate::Error;
use crate::ast::compute_line_starts;
use crate::core::{LanguageId, ParsedUnit};
use crate::error::GrammarError;

static PYTHON_LANGUAGE: OnceLock<Result<tree_sitter::Language, GrammarError>> = OnceLock::new();

fn python_language() -> Result<&'static tree_sitter::Language, GrammarError> {
    PYTHON_LANGUAGE
        .get_or_init(|| {
            let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
            let mut parser = Parser::new();
            parser
                .set_language(&lang)
                .map_err(|e| GrammarError::Load(e.to_string()))?;
            Ok(lang)
        })
        .as_ref()
        .map_err(|e| e.clone())
}

pub fn configure(parser: &mut Parser) -> Result<(), Error> {
    let lang = python_language()?;
    parser
        .set_language(lang)
        .map_err(|e| Error::Grammar(format!("tree-sitter-python: {e}")))?;
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
        language: LanguageId::Python,
        display_path: path.display().to_string(),
        path: path.to_path_buf(),
        source,
        tree,
        line_starts,
        function_spans: Vec::new(),
    })
}
