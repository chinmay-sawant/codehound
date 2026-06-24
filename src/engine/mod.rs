//! Analysis engine — orchestration only.

mod analyzer;
mod baseline;
mod config;
mod diagnostics;
mod ignore;
mod language_filter;
mod parse_pool;
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
pub use config::{
    BaselineConfig, PathFilters, SlopguardConfig, SlopguardSection, build_scan_context,
    discover_config, fail_on_to_policy, load_discovered_config,
};
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
