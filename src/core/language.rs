//! Language identification and plugin trait.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use super::{Detector, ParsedUnit};

/// Supported (or planned) languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageId {
    Go,
    Python,
    TypeScript,
}

impl LanguageId {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "go" => Some(Self::Go),
            "py" => Some(Self::Python),
            "ts" | "tsx" | "js" | "jsx" => Some(Self::TypeScript),
            _ => None,
        }
    }
}

/// Per-language backend: parse sources and supply detectors.
pub trait LanguagePlugin: Send + Sync {
    fn id(&self) -> LanguageId;
    fn extensions(&self) -> &'static [&'static str];
    /// Configure a reused tree-sitter parser (called once per language per scan).
    fn configure_parser(&self, parser: &mut tree_sitter::Parser);
    /// Parse with a pre-configured parser (hot path — no allocator per file).
    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: Arc<str>,
    ) -> Result<ParsedUnit>;
    fn detectors(&self) -> Vec<Box<dyn Detector>>;
    fn loop_node_kinds(&self) -> &'static [&'static str];

    /// One-shot parse (tests only); production uses [`parse_with`] + pool.
    fn parse(&self, path: &Path, source: Arc<str>) -> Result<ParsedUnit> {
        let mut parser = tree_sitter::Parser::new();
        self.configure_parser(&mut parser);
        self.parse_with(&mut parser, path, source)
    }
}
