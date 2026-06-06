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

    /// Parse a `slopguard.toml` / operator language name (e.g. `go`, `python`, `py`).
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "go" => Some(Self::Go),
            "python" | "py" => Some(Self::Python),
            "typescript" | "ts" => Some(Self::TypeScript),
            _ => None,
        }
    }

    pub fn config_names(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::Python => &["python", "py"],
            Self::TypeScript => &["typescript", "ts"],
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
    fn parse(&self, path: &Path, source: Arc<str>) -> Result<ParsedUnit> {
        let mut parser = tree_sitter::Parser::new();
        self.configure_parser(&mut parser);
        self.parse_with(&mut parser, path, source)
    }
}
