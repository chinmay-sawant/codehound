//! Per-language backend: parse sources and supply detectors.

use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::core::{Detector, ParsedUnit, ScanContext};

use super::id::LanguageId;

/// Language-neutral project context for dependency extraction.
///
/// Contains only fields every language can use without language-specific
/// module/package semantics. Plugins derive their own module data from
/// [`Self::root`] (for example, Go reads `go.mod` inside the plugin).
#[derive(Debug, Clone, Copy)]
pub struct ProjectContext<'a> {
    /// Resolved project root used as the base for local dependency paths.
    pub root: &'a Path,
}

impl<'a> ProjectContext<'a> {
    /// Build a context for the given project root.
    #[must_use]
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }
}

/// Per-language backend: parse sources and supply detectors.
pub trait LanguagePlugin: Send + Sync {
    /// Return the language implemented by this plugin.
    fn id(&self) -> LanguageId;
    /// Return source-file extensions accepted by this plugin.
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
    /// Detectors contributed by this language plugin.
    fn detectors(&self) -> Vec<Box<dyn Detector>>;
    /// Tree-sitter node kinds treated as loops for this language.
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

    /// One-shot parse (tests only); production uses [`Self::parse_with`] + pool.
    ///
    /// # Errors
    ///
    /// Returns the grammar or parse error reported by the plugin.
    fn parse(&self, path: &Path, source: Arc<str>) -> Result<ParsedUnit, Error> {
        let mut parser = tree_sitter::Parser::new();
        self.configure_parser(&mut parser)?;
        self.parse_with(&mut parser, path, source)
    }

    /// Optional project-level preparation before per-file work.
    ///
    /// Called once per top-level scan with the distinct discovered project
    /// roots for that scan. Language packs use this for pack-local prewarming
    /// (for example building a shared project snapshot) so the generic engine
    /// does not hardcode language-specific prep. Default: no-op.
    fn prepare_project(&self, _ctx: &ScanContext, _project_roots: &[&Path]) {}

    /// Project-local dependency paths for cache cascade (relative to
    /// [`ProjectContext::root`]).
    ///
    /// Default: no dependencies. Languages override without editing the engine
    /// match arm in [`crate::engine::extract_dependencies`]. Derive any
    /// language-specific module/package data from [`ProjectContext::root`];
    /// do not expect Go-shaped inputs from the engine.
    ///
    /// Paths may be absolute or already relative; the engine normalizes and
    /// deduplicates them for cache keys.
    fn extract_deps(&self, _unit: &ParsedUnit, _project: &ProjectContext<'_>) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(all(test, feature = "go"))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// Non-Go stub plugin: dependency extraction uses only [`ProjectContext::root`].
    struct PathOnlyPlugin;

    impl LanguagePlugin for PathOnlyPlugin {
        fn id(&self) -> LanguageId {
            LanguageId::Python
        }

        fn extensions(&self) -> &'static [&'static str] {
            &["py"]
        }

        fn configure_parser(&self, _parser: &mut tree_sitter::Parser) -> Result<(), crate::Error> {
            // Not used by extract_deps tests.
            Ok(())
        }

        fn parse_with(
            &self,
            _parser: &mut tree_sitter::Parser,
            _path: &Path,
            _source: Arc<str>,
        ) -> Result<ParsedUnit, crate::Error> {
            Err(crate::Error::Parse {
                path: _path.display().to_string(),
                detail: "PathOnlyPlugin does not parse".into(),
            })
        }

        fn detectors(&self) -> Vec<Box<dyn Detector>> {
            Vec::new()
        }

        fn loop_node_kinds(&self) -> &'static [&'static str] {
            &[]
        }

        fn extract_deps(&self, _unit: &ParsedUnit, project: &ProjectContext<'_>) -> Vec<String> {
            // Language-local dependency discovery from neutral root only —
            // no module_prefix / go.mod inputs from the engine.
            vec![
                project
                    .root
                    .join("lib")
                    .join("util.py")
                    .to_string_lossy()
                    .into_owned(),
            ]
        }
    }

    fn dummy_unit() -> ParsedUnit {
        // Borrow Go grammar only to build a Tree; language id is Python so
        // this is clearly not Go-plugin dependency extraction.
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("set go language");
        let source: Arc<str> = Arc::from("package main\n");
        let tree = parser
            .parse(source.as_ref(), None)
            .expect("parse dummy go source");
        ParsedUnit::new(
            LanguageId::Python,
            PathBuf::from("main.py"),
            source,
            tree,
            vec![0],
            Vec::new(),
        )
    }

    #[test]
    fn non_go_plugin_extract_deps_uses_only_project_root() {
        let root = PathBuf::from("/tmp/proj");
        let project = ProjectContext::new(&root);
        let unit = dummy_unit();
        let deps = PathOnlyPlugin.extract_deps(&unit, &project);
        assert_eq!(deps, vec!["/tmp/proj/lib/util.py".to_string()]);
    }
}
