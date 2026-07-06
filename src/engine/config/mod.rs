//! Optional `slopguard.toml` configuration.

mod discover;
mod scan_context;
mod section;
mod types;

pub use discover::{
    discover_cache_dir, discover_config, fail_on_to_policy, load_discovered_config,
};
pub use scan_context::{build_scan_context, ScanContextParams};
pub use types::{BaselineConfig, CacheConfig, PathFilters, SlopguardConfig, SlopguardSection};
