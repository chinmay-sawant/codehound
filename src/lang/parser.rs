//! Shared tree-sitter language initialisation and per-language marker types.

use std::path::Path;
use std::sync::Arc;

use tree_sitter::{Language, Parser};

use crate::Error;
use crate::ast::compute_line_starts;
use crate::core::{LanguageId, ParsedUnit};

/// Per-language marker trait. Each language defines a zero-sized type
/// implementing this trait so that [`configure`] and [`parse_with`]
/// can be generic over the language.
pub trait TreeSitterLang {
    const ID: LanguageId;
    const ERROR_TAG: &'static str;
    fn language() -> Language;
}

/// Generic [`configure`] replacement. Callers invoke
/// `parser::configure::<GoLang>(&mut parser)`.
///
/// # Errors
///
/// Returns [`Error::Grammar`] when tree-sitter rejects the language grammar.
pub fn configure<L: TreeSitterLang>(parser: &mut Parser) -> Result<(), Error> {
    let lang = L::language();
    parser
        .set_language(&lang)
        .map_err(|e| Error::Grammar(format!("{}: {e}", L::ERROR_TAG)))?;
    Ok(())
}

/// Generic [`parse_with`] replacement. Callers invoke
/// `parser::parse_with::<GoLang>(&mut parser, path, source)`.
///
/// # Errors
///
/// Returns [`Error::Parse`] when tree-sitter does not produce a syntax tree.
pub fn parse_with<L: TreeSitterLang>(
    parser: &mut Parser,
    path: &Path,
    source: Arc<str>,
) -> Result<ParsedUnit, Error> {
    let tree = parser
        .parse(source.as_ref(), None)
        .ok_or_else(|| Error::Parse {
            path: path.display().to_string(),
            detail: "tree-sitter returned None".to_string(),
        })?;
    let line_starts = compute_line_starts(&source);
    Ok(ParsedUnit {
        language: L::ID,
        display_path: path.display().to_string(),
        path: path.to_path_buf(),
        source,
        tree,
        line_starts,
        function_spans: Vec::new(),
    })
}

// ── Marker types are now defined by `tree_sitter_lang!` in each
// language's module ────────────────────────────────────────────────────

/// Convenience helper for Go detector unit tests.
#[cfg(feature = "go")]
#[cfg(test)]
pub fn parse_go(source: &str) -> Result<ParsedUnit, Error> {
    let mut parser = Parser::new();
    configure::<crate::lang::go::GoLang>(&mut parser)?;
    parse_with::<crate::lang::go::GoLang>(&mut parser, Path::new("sample.go"), Arc::from(source))
}
