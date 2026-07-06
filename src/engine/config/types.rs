//! `slopguard.toml` configuration types.

use std::path::PathBuf;

use serde::Deserialize;

use crate::rules::Severity;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlopguardConfig {
    #[serde(default)]
    pub slopguard: SlopguardSection,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlopguardSection {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub skip: Vec<String>,
    #[serde(default)]
    pub only: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub exclude_tests: Option<bool>,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub taint: TaintConfig,
    #[serde(default)]
    pub bad_practices: BadPracticesConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaselineConfig {
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

/// Incremental-analysis cache configuration. Mirrors the `--no-cache` /
/// `--cache-dir` CLI flags. When `enabled = false` the cache is not
/// opened or written; when `path` is `Some`, that directory is used
/// instead of the auto-discovered `<project>/.slopguard-cache/`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    pub path: Option<PathBuf>,

    /// Maximum on-disk size of the cache directory in MiB.
    /// When exceeded, the oldest entries (by `cached_at` timestamp)
    /// are evicted during `flush()`. Default: 500 MiB.
    /// Set to `0` to disable the size limit.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// Evict down to this fraction of `max_size_mb` once the limit is exceeded.
    #[serde(default = "default_evict_target_ratio")]
    pub evict_target_ratio: Option<f64>,
    /// Skip reading/writing cache entries for files larger than this size in MiB.
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: Option<u64>,
}

fn default_max_size_mb() -> u64 {
    500
}

fn default_evict_target_ratio() -> Option<f64> {
    Some(0.9)
}

fn default_max_file_size_mb() -> Option<u64> {
    Some(4)
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            max_size_mb: default_max_size_mb(),
            evict_target_ratio: default_evict_target_ratio(),
            max_file_size_mb: default_max_file_size_mb(),
        }
    }
}

/// Experimental taint-tracking configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct TaintConfig {
    pub enabled: Option<bool>,
    pub show_paths: Option<bool>,
}

/// Go bad-practice rule configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BadPracticesConfig {
    pub enabled: bool,
    pub severity: Option<Severity>,
}

impl Default for BadPracticesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFilters {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub exclude_tests: bool,
}

impl Default for PathFilters {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            exclude_tests: true,
        }
    }
}
