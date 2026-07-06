//! [`AnalyzerBuilder`] — fluent builder for [`Analyzer`].

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::walk::EntrySource;

use super::types::Analyzer;

struct BuilderFields {
    ctx: ScanContext,
    registry: Registry,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
    collect_stats: bool,
    entry_source: Option<Box<dyn EntrySource>>,
}

/// Configures an [`Analyzer`].
pub struct AnalyzerBuilder {
    fields: BuilderFields,
}

impl AnalyzerBuilder {
    #[must_use = "configure the analyzer before calling build()"]
    pub(crate) fn new() -> Self {
        Self {
            fields: BuilderFields {
                ctx: ScanContext::default(),
                registry: Registry::default(),
                lang_filter: LanguageFilter::default(),
                path_filters: PathFilters::default(),
                collect_stats: false,
                entry_source: None,
            },
        }
    }

    pub fn scan_context(mut self, ctx: ScanContext) -> Self {
        self.fields.ctx = ctx;
        self
    }

    pub fn registry(mut self, registry: Registry) -> Self {
        self.fields.registry = registry;
        self
    }

    pub fn path_filters(mut self, filters: PathFilters) -> Self {
        self.fields.path_filters = filters;
        self
    }

    pub fn collect_stats(mut self, collect: bool) -> Self {
        self.fields.collect_stats = collect;
        self
    }

    /// Accept the default language filter (`All`). Retained for
    /// callers that previously needed the type-state transition.
    pub fn with_default_filter(self) -> Self {
        self
    }

    pub fn language_filter(mut self, filter: LanguageFilter) -> Self {
        self.fields.lang_filter = filter;
        self
    }

    /// Inject a custom entry source (e.g. [`ListEntrySource`] for tests).
    /// When not set, the default [`FilesystemWalker`] is used.
    pub fn entry_source(mut self, source: Box<dyn EntrySource>) -> Self {
        self.fields.entry_source = Some(source);
        self
    }

    pub fn build(self) -> Analyzer {
        Analyzer {
            registry: self.fields.registry,
            ctx: self.fields.ctx,
            lang_filter: self.fields.lang_filter,
            path_filters: self.fields.path_filters,
            collect_stats: self.fields.collect_stats,
            project_root: std::path::PathBuf::default(),
            module_prefix: None,
            entry_source: self.fields.entry_source,
        }
    }
}

impl Analyzer {
    #[must_use = "configure the analyzer before calling build()"]
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::new()
    }
}
