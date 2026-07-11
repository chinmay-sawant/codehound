//! Per-language backend: parse sources and supply detectors.

use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::core::{Detector, ParsedUnit};

use super::id::LanguageId;

pub trait LanguagePlugin: Send + Sync {
    fn id(&self) -> LanguageId;
    fn extensions(&self) -> &'static [&'static str];
    /// Configure a reused tree-sitter parser (called once per language per scan).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Grammar`] when the tree-sitter grammar failed to load.
    fn configure_parser(&self, parser: &mut tree_sitter::Parser) -> Result<(), Error>;
    /// Parse with a pre-configured parser (hot path — no allocator per file).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] when tree-sitter cannot build a syntax tree, or
    /// [`Error::Grammar`] when the parser was not configured.
    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: Arc<str>,
    ) -> Result<ParsedUnit, Error>;
    fn detectors(&self) -> Vec<Box<dyn Detector>>;
    fn loop_node_kinds(&self) -> &'static [&'static str];

    /// Node kinds that should be treated as function-like when resolving the
    /// enclosing scope of a finding (e.g. `function_declaration` and
    /// `method_declaration` in Go). Plugins that do not override this get an
    /// empty list, which disables function-context resolution for the
    /// language — the exporter then falls back to its default "few lines
    /// before/after" window.
    fn function_node_kinds(&self) -> &'static [&'static str] {
        &[]
    }

    /// One-shot parse (tests only); production uses [`parse_with`] + pool.
    fn parse(&self, path: &Path, source: Arc<str>) -> Result<ParsedUnit, Error> {
        let mut parser = tree_sitter::Parser::new();
        self.configure_parser(&mut parser)?;
        self.parse_with(&mut parser, path, source)
    }

    /// Project-local dependency paths for cache cascade (relative to `project_root`).
    ///
    /// Default: no dependencies. Languages override without editing the engine
    /// match arm in [`crate::engine::extract_dependencies`].
    fn extract_deps(
        &self,
        _unit: &ParsedUnit,
        _project_root: &Path,
        _module_prefix: Option<&str>,
    ) -> Vec<String> {
        Vec::new()
    }
}
