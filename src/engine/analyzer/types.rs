//! `Analyzer` type.

use std::path::PathBuf;

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;

/// Language-agnostic static analyzer.
pub struct Analyzer {
    pub(super) registry: Registry,
    pub ctx: ScanContext,
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


