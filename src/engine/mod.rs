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
    SlopguardConfig, SlopguardSection, build_scan_context, discover_config, load_discovered_config,
};
pub use language_filter::{LanguageFilter, resolve_language_filter};
pub use registry::Registry;
pub use result::{AnalysisResult, ScanError, ScanErrorKind};

/// Process large entry lists in bounded chunks to cap parallel work memory.
pub const SCAN_CHUNK_SIZE: usize = 1024;
