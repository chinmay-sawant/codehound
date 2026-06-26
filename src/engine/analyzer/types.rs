//! `Analyzer` and `AnalyzerBuilder` types.

use std::path::{Path, PathBuf};

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::dependencies::{discover_project_root, go_module_prefix};
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;

#[derive(Default)]
pub struct AnalyzerBuilder {
    pub(super) ctx: ScanContext,
    pub(super) registry: Option<Registry>,
    pub(super) lang_filter: LanguageFilter,
    pub(super) path_filters: PathFilters,
    pub(super) collect_stats: bool,
}

impl AnalyzerBuilder {
    pub fn scan_context(mut self, ctx: ScanContext) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn language_filter(mut self, filter: LanguageFilter) -> Self {
        self.lang_filter = filter;
        self
    }

    pub fn path_filters(mut self, filters: PathFilters) -> Self {
        self.path_filters = filters;
        self
    }

    pub fn collect_stats(mut self, collect: bool) -> Self {
        self.collect_stats = collect;
        self
    }

    pub fn build(self) -> Analyzer {
        let project_root = discover_project_root(Path::new("."));
        let module_prefix = go_module_prefix(&project_root);
        Analyzer {
            registry: self.registry.unwrap_or_default(),
            ctx: self.ctx,
            lang_filter: self.lang_filter,
            path_filters: self.path_filters,
            collect_stats: self.collect_stats,
            project_root,
            module_prefix,
        }
    }
}

/// Language-agnostic static analyzer.
pub struct Analyzer {
    pub(super) registry: Registry,
    pub(super) ctx: ScanContext,
    pub(super) lang_filter: LanguageFilter,
    pub(super) path_filters: PathFilters,
    pub(super) collect_stats: bool,
    /// Resolved at build time. Falls back to the cwd when the scan
    /// path has no enclosing `.git`.
    pub(super) project_root: PathBuf,
    /// `module` directive from the project root's `go.mod`, when
    /// present. Used to distinguish local Go imports from
    /// stdlib / third-party.
    pub(super) module_prefix: Option<String>,
}

impl Analyzer {
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::default()
    }

    pub fn scan_context(&self) -> &ScanContext {
        &self.ctx
    }
}
