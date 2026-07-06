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
    /// Optional pluggable entry source. When `None`, the default
    /// [`FilesystemWalker`](crate::engine::walk::FilesystemWalker) is used.
    pub(super) entry_source: Option<Box<dyn EntrySource>>,
}
