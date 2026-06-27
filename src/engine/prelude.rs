//! Curated re-exports for typical library consumers.

pub use super::analyzer::{Analyzer, AnalyzerBuilder};
pub use super::config::{
    SlopguardConfig, build_scan_context, discover_config, load_discovered_config,
};
pub use super::language_filter::{LanguageFilter, resolve_language_filter};
pub use super::registry::Registry;
pub use super::result::AnalysisResult;
pub use super::walk::collect_entries;
