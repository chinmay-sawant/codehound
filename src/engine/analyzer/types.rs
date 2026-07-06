//! `Analyzer` type.

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::walk::EntrySource;

/// Language-agnostic static analyzer.
pub struct Analyzer {
    pub(super) registry: Registry,
    pub ctx: ScanContext,
    pub(super) lang_filter: LanguageFilter,
    pub(super) path_filters: PathFilters,
    pub(super) collect_stats: bool,
    /// Pluggable entry source; defaults to [`FilesystemWalker`](crate::engine::walk::FilesystemWalker).
    pub(super) entry_source: Box<dyn EntrySource>,
}
