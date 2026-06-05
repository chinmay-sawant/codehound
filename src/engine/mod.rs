//! Analysis engine — orchestration only.

mod analyzer;
mod config;
mod language_filter;
mod parse_pool;
mod registry;
mod result;
mod walk;

pub use analyzer::{Analyzer, AnalyzerBuilder};
pub use config::{
    PathFilters, SlopguardConfig, SlopguardSection, build_scan_context, discover_config,
    fail_on_to_policy, load_discovered_config,
};
pub use language_filter::{LanguageFilter, resolve_language_filter};
pub use registry::Registry;
pub use result::{AnalysisResult, ScanError, ScanErrorKind};
pub use walk::scratch_contains;

/// Process large entry lists in bounded chunks to cap parallel work memory.
pub const SCAN_CHUNK_SIZE: usize = 1024;
