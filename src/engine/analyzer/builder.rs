//! [`AnalyzerBuilder`] — fluent builder for [`Analyzer`].

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::walk::EntrySource;

use super::types::Analyzer;

/// Configures an [`Analyzer`].
pub struct AnalyzerBuilder {
    ctx: ScanContext,
    registry: Registry,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
    collect_stats: bool,
    entry_source: Option<Box<dyn EntrySource>>,
}

impl AnalyzerBuilder {
    #[must_use = "configure the analyzer before calling build()"]
    pub(crate) fn new() -> Self {
        Self {
            ctx: ScanContext::default(),
            registry: Registry::default(),
            lang_filter: LanguageFilter::default(),
            path_filters: PathFilters::default(),
            collect_stats: false,
            entry_source: None,
        }
    }

    pub fn scan_context(mut self, ctx: ScanContext) -> Self {
        self.ctx = ctx;
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

    pub fn language_filter(mut self, filter: LanguageFilter) -> Self {
        self.lang_filter = filter;
        self
    }

    /// Inject a custom entry source (e.g. [`ListEntrySource`] for tests).
    /// When not set, the default [`FilesystemWalker`] is used.
    pub fn entry_source(mut self, source: Box<dyn EntrySource>) -> Self {
        self.entry_source = Some(source);
        self
    }

    pub fn build(self) -> Analyzer {
        Analyzer {
            registry: self.registry,
            ctx: self.ctx,
            lang_filter: self.lang_filter,
            path_filters: self.path_filters,
            collect_stats: self.collect_stats,
            entry_source: self.entry_source,
        }
    }
}

impl Analyzer {
    #[must_use = "configure the analyzer before calling build()"]
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::new()
    }
}