//! Optional `slopguard.toml` configuration.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::core::{FailPolicy, ScanContext};
use crate::engine::DEFAULT_CACHE_DIR;

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
}

fn default_max_size_mb() -> u64 {
    500
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            max_size_mb: default_max_size_mb(),
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

impl SlopguardConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).context("parsing slopguard.toml")
    }

    pub fn discover() -> Option<Self> {
        load_discovered_config().ok().flatten()
    }

    /// Merge this config into a `ScanContext`. CLI-set fields take precedence:
    /// `skip` and `only` are merged additively, but
    /// `fail_policy` is only applied when the CLI did not pass an explicit
    /// one (signaled by `cli_set_fail_policy`).
    pub fn merge_into(self, mut ctx: ScanContext, cli_set_fail_policy: bool) -> ScanContext {
        if !self.slopguard.skip.is_empty() {
            ctx.skip.extend(self.slopguard.skip);
        }
        if !self.slopguard.only.is_empty() {
            let mut only = ctx.only.take().unwrap_or_default();
            only.extend(self.slopguard.only);
            ctx.only = Some(only);
        }
        if let Some(fail_on) = self.slopguard.fail_on.as_deref() {
            if !cli_set_fail_policy {
                ctx.fail_policy = fail_on_to_policy(fail_on);
            }
        }
        ctx
    }

    pub fn include(&self) -> &[String] {
        &self.slopguard.include
    }

    pub fn exclude(&self) -> &[String] {
        &self.slopguard.exclude
    }

    pub fn path_filters(&self) -> PathFilters {
        PathFilters {
            include: self.slopguard.include.clone(),
            exclude: self.slopguard.exclude.clone(),
            exclude_tests: self.slopguard.exclude_tests.unwrap_or(true),
        }
    }

    pub fn baseline_enabled(&self) -> bool {
        self.slopguard.baseline.enabled
    }

    pub fn baseline_path(&self) -> Option<PathBuf> {
        self.slopguard.baseline.path.clone()
    }

    /// `false` only when the user explicitly disabled the cache in
    /// `slopguard.toml`. Default is `true` (cache on).
    pub fn cache_enabled(&self) -> bool {
        self.slopguard.cache.enabled
    }

    /// Custom cache directory, if any. When `None`, the caller is
    /// responsible for auto-discovery (or the CLI-provided override).
    pub fn cache_path(&self) -> Option<PathBuf> {
        self.slopguard.cache.path.clone()
    }
}

/// Walk from `start` upward looking for the closest `.slopguard-cache/`
/// directory. Returns `None` if none is found in the chain. Used when
/// the user did not set `cache.path` in `slopguard.toml` and did not
/// pass `--cache-dir`.
pub fn discover_cache_dir(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        let candidate = current.join(DEFAULT_CACHE_DIR);
        if candidate.is_dir() {
            return Some(candidate);
        }
        if current.join(".git").is_dir() {
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}

#[doc(hidden)]
pub fn fail_on_to_policy(s: &str) -> FailPolicy {
    match s.to_lowercase().as_str() {
        "none" | "never" => FailPolicy::NoFail,
        "high" | "strict" => FailPolicy::Strict,
        "medium" | "warning" => FailPolicy::MediumAsErrors,
        _ => FailPolicy::MediumAsErrors,
    }
}

/// Walk from `start` upward looking for the closest `slopguard.toml`.
pub fn discover_config(start: &Path) -> Option<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("slopguard.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Load `slopguard.toml` from the current directory when present.
pub fn load_discovered_config() -> Result<Option<SlopguardConfig>> {
    let path = Path::new("slopguard.toml");
    if path.is_file() {
        Ok(Some(SlopguardConfig::load(path)?))
    } else {
        Ok(None)
    }
}

/// Build scan context from CLI + optional config file.
pub fn build_scan_context(
    only: Vec<String>,
    skip: Vec<String>,
    fail_policy: FailPolicy,
    config: Option<SlopguardConfig>,
    cli_set_fail_policy: bool,
    debug_timing: bool,
    diagnostics: bool,
) -> ScanContext {
    let mut ctx = ScanContext {
        only: if only.is_empty() {
            None
        } else {
            Some(only.into_iter().collect())
        },
        skip: skip.into_iter().collect(),
        fail_policy,
        show_ignored: false,
        debug_timing,
        diagnostics,
    };
    if let Some(cfg) = config {
        ctx = cfg.merge_into(ctx, cli_set_fail_policy);
    }
    ctx
}
