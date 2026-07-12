//! Optional `codehound.toml` configuration.

mod discover;
mod run_config;
mod scan_context;
mod types;

pub use discover::{discover_cache_dir, discover_config};
pub use run_config::{RunConfig, RunConfigParams, build_run_config, path_filters_from_config};
pub use scan_context::{ScanContextParams, build_scan_context};
pub use types::{CacheConfig, CodehoundConfig, CodehoundSection, PathFilters};
