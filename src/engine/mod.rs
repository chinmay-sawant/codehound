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
mod path_walk;
pub mod prelude;
mod registry;
mod result;
pub mod sinks;
mod stats;
pub(crate) mod time;
mod timing;
mod walk;

pub use analyzer::{Analyzer, AnalyzerBuilder};
pub use baseline::{BASELINE_FILE_NAME, BASELINE_VERSION, Baseline, discover_baseline};
pub use cache::{
    CACHE_VERSION, CacheEntry, CacheError, CacheLookup, CacheManifest, CacheStore,
    DEFAULT_CACHE_DIR, cache_key_for_path, content_hash,
};
pub use config::{
    BaselineConfig, CacheConfig, PathFilters, ScanContextParams, SlopguardConfig, SlopguardSection,
    build_scan_context, discover_cache_dir, discover_config,
};
pub use dependencies::{discover_project_root, extract_dependencies, go_module_prefix};
pub use diagnostics::Diagnostics;
pub use ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
pub use language_filter::{LanguageFilter, resolve_language_filter};
pub use registry::Registry;
pub(crate) use result::PipelineAccumulator;
pub use result::{AnalysisResult, ScanError, ScanErrorKind};
pub use stats::{FileStats, ScanStats};
pub use timing::{PhaseTiming, TimingCollector, TimingSpan, TimingSummary};
pub use walk::{
    EntrySource, FilesystemWalker, ListEntrySource, ScanEntry, analyze_parsed_unit_with_context,
    collect_entries, scratch_contains,
};

/// Process large entry lists in bounded chunks to cap parallel work memory.
pub const SCAN_CHUNK_SIZE: usize = 1024;
