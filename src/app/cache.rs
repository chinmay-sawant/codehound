use std::path::{Path, PathBuf};

use codehound::cli::Cli;
use codehound::engine::{CacheStore, CodehoundConfig, DEFAULT_CACHE_DIR, discover_cache_dir};

/// Resolve and open the incremental-analysis cache when enabled by
/// CLI flags + `codehound.toml`. Returns `None` when the cache is
/// disabled (`--no-cache` or `cache.enabled = false`) or when the
/// directory cannot be opened.
pub(crate) fn open_cache_store(cli: &Cli, config: Option<&CodehoundConfig>) -> Option<CacheStore> {
    if cli.no_cache {
        return None;
    }
    if let Some(cfg) = config {
        if !cfg.codehound.cache.enabled {
            return None;
        }
    }
    let dir = cache_directory(cli, config);
    let cache_cfg = config.map(|c| &c.codehound.cache);
    let max_size_mb = cache_cfg.map(|c| c.max_size_mb).unwrap_or(500);
    let evict_target_ratio = cache_cfg.and_then(|c| c.evict_target_ratio).unwrap_or(0.9);
    let max_file_size_mb = cache_cfg.and_then(|c| c.max_file_size_mb).unwrap_or(4);
    match CacheStore::open_with_limits(dir, max_size_mb, evict_target_ratio, max_file_size_mb) {
        Ok(s) => Some(s),
        Err(e) => {
            if !cli.quiet {
                tracing::warn!("could not open incremental cache: {e:#}");
            }
            None
        }
    }
}

/// Resolve the cache directory following CLI > config > auto-discovery
/// precedence, falling back to [`DEFAULT_CACHE_DIR`].
pub(crate) fn cache_directory(cli: &Cli, config: Option<&CodehoundConfig>) -> PathBuf {
    if let Some(dir) = &cli.cache_dir {
        return dir.clone();
    }
    if let Some(cfg) = config {
        if let Some(p) = &cfg.codehound.cache.path {
            return p.clone();
        }
    }
    if let Some(found) = discover_cache_dir(Path::new(".")) {
        return found;
    }
    Path::new(DEFAULT_CACHE_DIR).to_path_buf()
}
