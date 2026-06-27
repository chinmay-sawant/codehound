//! Type-state [`AnalyzerBuilder`] — `build()` requires an explicit language filter.

use std::marker::PhantomData;
use std::path::Path;

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::dependencies::{discover_project_root, go_module_prefix};
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;

use super::types::Analyzer;

/// Language filter not yet set on the builder.
pub struct UnsetFilter;
/// Language filter configured (or defaulted via [`AnalyzerBuilder::with_default_filter`]).
pub struct HasFilter;

struct BuilderFields {
    ctx: ScanContext,
    registry: Option<Registry>,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
    collect_stats: bool,
}

/// Configures an [`Analyzer`]. Call [`language_filter`](Self::language_filter) or
/// [`with_default_filter`](Self::with_default_filter) before [`build`](Self::build).
pub struct AnalyzerBuilder<FilterState = UnsetFilter> {
    fields: BuilderFields,
    _filter: PhantomData<FilterState>,
}

macro_rules! builder_setters {
    ($state:ty) => {
        impl AnalyzerBuilder<$state> {
            pub fn scan_context(mut self, ctx: ScanContext) -> Self {
                self.fields.ctx = ctx;
                self
            }

            pub fn registry(mut self, registry: Registry) -> Self {
                self.fields.registry = Some(registry);
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
        }
    };
}

impl AnalyzerBuilder<UnsetFilter> {
    #[must_use = "configure the analyzer before calling build()"]
    pub(crate) fn new() -> Self {
        Self {
            fields: BuilderFields {
                ctx: ScanContext::default(),
                registry: None,
                lang_filter: LanguageFilter::default(),
                path_filters: PathFilters::default(),
                collect_stats: false,
            },
            _filter: PhantomData,
        }
    }

    /// Accept the default language filter (`All`) and allow [`build`](Self::build).
    #[must_use = "call build() on the configured builder"]
    pub fn with_default_filter(self) -> AnalyzerBuilder<HasFilter> {
        AnalyzerBuilder {
            fields: self.fields,
            _filter: PhantomData,
        }
    }

    /// Set the language filter; required before [`build`](Self::build).
    #[must_use = "call build() on the configured builder"]
    pub fn language_filter(self, filter: LanguageFilter) -> AnalyzerBuilder<HasFilter> {
        AnalyzerBuilder {
            fields: BuilderFields {
                lang_filter: filter,
                ..self.fields
            },
            _filter: PhantomData,
        }
    }
}

builder_setters!(UnsetFilter);
builder_setters!(HasFilter);

impl AnalyzerBuilder<HasFilter> {
    pub fn language_filter(mut self, filter: LanguageFilter) -> Self {
        self.fields.lang_filter = filter;
        self
    }

    pub fn build(self) -> Analyzer {
        let project_root = discover_project_root(Path::new("."));
        let module_prefix = go_module_prefix(&project_root);
        Analyzer {
            registry: self.fields.registry.unwrap_or_default(),
            ctx: self.fields.ctx,
            lang_filter: self.fields.lang_filter,
            path_filters: self.fields.path_filters,
            collect_stats: self.fields.collect_stats,
            project_root,
            module_prefix,
        }
    }
}

impl Analyzer {
    #[must_use = "configure the analyzer before calling build()"]
    pub fn builder() -> AnalyzerBuilder<UnsetFilter> {
        AnalyzerBuilder::new()
    }
}
