//! `codehound.toml` configuration types.

use std::path::PathBuf;

use serde::Deserialize;

use crate::rules::Severity;

/// Root document for `codehound.toml`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodehoundConfig {
    /// Top-level `[codehound]` section.
    #[serde(default)]
    pub codehound: CodehoundSection,
}

/// Contents of the `[codehound]` TOML table.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodehoundSection {
    /// Enabled language names (e.g. `"go"`, `"python"`).
    #[serde(default)]
    pub languages: Vec<String>,
    /// Exit policy name (`"high"`, `"medium"`, `"never"`, …).
    #[serde(default)]
    pub fail_on: Option<String>,
    /// Rule IDs / globs to skip.
    #[serde(default)]
    pub skip: Vec<String>,
    /// Rule IDs / globs to run exclusively when non-empty.
    #[serde(default)]
    pub only: Vec<String>,
    /// Glob include filters for scanned paths.
    #[serde(default)]
    pub include: Vec<String>,
    /// Glob exclude filters for scanned paths.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// When `Some(true)`, skip test files; `None` uses engine default.
    #[serde(default)]
    pub exclude_tests: Option<bool>,
    /// Baseline adoption settings.
    #[serde(default)]
    pub baseline: BaselineConfig,
    /// Incremental analysis cache settings.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Experimental taint-tracking settings.
    #[serde(default)]
    pub taint: TaintConfig,
    /// Go bad-practice pack settings.
    #[serde(default)]
    pub bad_practices: BadPracticesConfig,
}

/// Baseline file configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaselineConfig {
    /// Whether baseline filtering is enabled.
    pub enabled: bool,
    /// Optional explicit baseline path (otherwise auto-discovered).
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
/// instead of the auto-discovered `<project>/.codehound-cache/`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Whether the incremental cache is used for this run.
    pub enabled: bool,
    /// Optional custom cache directory.
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
    /// Explicit enable/disable; `None` leaves profile defaults in control.
    pub enabled: Option<bool>,
    /// When true, attach taint-path evidence to findings.
    pub show_paths: Option<bool>,
}

/// Go bad-practice rule configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BadPracticesConfig {
    /// Whether the bad-practice pack is enabled.
    pub enabled: bool,
    /// Optional default severity override for all BP rules.
    pub severity: Option<Severity>,
    /// Per-rule severity overrides keyed by rule ID (e.g. `"BP-1" = "high"`).
    #[serde(default)]
    pub severity_overrides: std::collections::HashMap<String, Severity>,
}

impl Default for BadPracticesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: None,
            severity_overrides: std::collections::HashMap::new(),
        }
    }
}

/// Path include/exclude filters applied during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFilters {
    /// Glob include patterns (empty = include all).
    pub include: Vec<String>,
    /// Glob exclude patterns.
    pub exclude: Vec<String>,
    /// When true, skip common test file patterns.
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
