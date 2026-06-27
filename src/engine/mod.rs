//! Analysis engine — orchestration only.

mod analyzer;
mod baseline;
mod cache;
mod config;
mod dependencies;
mod diagnostics;
mod ignore;
mod language_filter;
mod parse_pool;
pub mod prelude;
mod registry;
mod result;
pub mod sinks;
mod stats;
mod timing;
mod walk;

pub use analyzer::{Analyzer, AnalyzerBuilder};
pub use baseline::{
    BASELINE_FILE_NAME, BASELINE_VERSION, Baseline, BaselineEntry, discover_baseline,
};
pub use cache::{
    CACHE_VERSION, CacheEntry, CacheError, CacheLookup, CacheManifest, CacheMetadata, CacheStore,
    DEFAULT_CACHE_DIR, FileCacheMeta, cache_key_for_path, content_hash,
};
pub use config::{
    BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection,
    build_scan_context, discover_cache_dir, discover_config, fail_on_to_policy,
    load_discovered_config,
};
pub use dependencies::{discover_project_root, extract_dependencies, go_module_prefix};
pub use diagnostics::Diagnostics;
pub use ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
pub use language_filter::{LanguageFilter, resolve_language_filter};
pub use registry::Registry;
pub use result::{AnalysisResult, ScanError, ScanErrorKind};
pub use stats::{FileStats, ScanStats};
pub use timing::{PhaseTiming, TimingCollector, TimingSpan, TimingSummary};
pub use walk::{
    analyze_parsed_unit, analyze_parsed_unit_with_context, collect_entries, scratch_contains,
};

/// Process large entry lists in bounded chunks to cap parallel work memory.
pub const SCAN_CHUNK_SIZE: usize = 1024;
