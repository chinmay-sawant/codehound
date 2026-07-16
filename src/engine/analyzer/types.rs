//! `Analyzer` type.

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::walk::EntrySource;
use std::sync::Mutex;

/// Language-agnostic static analyzer.
pub struct Analyzer {
    pub(super) registry: Registry,
    /// Scan policy used by this analyzer.
    pub(crate) ctx: ScanContext,
    pub(super) lang_filter: LanguageFilter,
    pub(super) path_filters: PathFilters,
    pub(super) collect_stats: bool,
    /// Project-level detector state is scoped to one top-level scan.
    pub(super) scan_gate: Mutex<()>,
    /// Pluggable entry source; defaults to [`FilesystemWalker`](crate::engine::walk::FilesystemWalker).
    pub(super) entry_source: Box<dyn EntrySource>,
}

impl Analyzer {
    /// Return the immutable scan policy used by this analyzer.
    #[must_use]
    pub fn scan_context(&self) -> &ScanContext {
        &self.ctx
    }
}
