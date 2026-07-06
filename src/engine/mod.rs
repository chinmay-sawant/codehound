//! Analysis engine — orchestration only.

mod analyzer;
mod baseline;
mod cache;
mod config;
mod dependencies;
mod diagnostics;
mod ignore;
mod io;
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
    CacheBackend, CacheEntry, CacheError, CacheLookup, CacheManifest, CacheSession, CacheStore,
    DEFAULT_CACHE_DIR, InMemoryBackend, cache_key_for_path, content_hash,
};
pub use config::{
    CacheConfig, PathFilters, RunConfig, RunConfigParams, ScanContextParams, SlopguardConfig,
    SlopguardSection, build_run_config, build_scan_context, discover_cache_dir, discover_config,
    path_filters_from_config,
};
pub use dependencies::{discover_project_root, extract_dependencies, go_module_prefix};
pub use diagnostics::Diagnostics;
pub use ignore::{IgnoreDirective, parse_file_ignore, parse_inline_ignores};
pub use language_filter::{LanguageFilter, resolve_language_filter};
pub use registry::Registry;
pub(crate) use result::PipelineAccumulator;
pub use result::{AnalysisResult, ScanError, ScanErrorKind};
pub use stats::ScanStats;
pub use timing::{PhaseTiming, TimingCollector, TimingSummary};
pub use walk::{
    EntrySource, FilesystemWalker, ListEntrySource, ScanEntry, collect_entries,
    collect_entries_with, scratch_contains,
};

/// Process large entry lists in bounded chunks to cap parallel work memory.
pub const SCAN_CHUNK_SIZE: usize = 1024;
