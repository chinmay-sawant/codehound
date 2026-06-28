use std::path::{Path, PathBuf};

use slopguard::cli::Cli;
use slopguard::engine::{CacheStore, DEFAULT_CACHE_DIR, SlopguardConfig, discover_cache_dir};

/// Resolve and open the incremental-analysis cache when enabled by
/// CLI flags + `slopguard.toml`. Returns `None` when the cache is
/// disabled (`--no-cache` or `cache.enabled = false`) or when the
/// directory cannot be opened.
pub(crate) fn open_cache_store(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<CacheStore> {
    if cli.no_cache {
        return None;
    }
    if let Some(cfg) = config {
        if !cfg.slopguard.cache.enabled {
            return None;
        }
    }
    let dir = cache_directory(cli, config)?;
    let max_size_mb = config.map(|c| c.slopguard.cache.max_size_mb).unwrap_or(500);
    match CacheStore::open_with_capacity(dir, max_size_mb) {
        Ok(s) => Some(s),
        Err(e) => {
            if !cli.quiet {
                eprintln!("warning: could not open incremental cache: {e:#}");
            }
            None
        }
    }
}

/// Resolve the cache directory following CLI > config > auto-discovery
/// precedence. Returns `None` when none of the sources apply.
pub(crate) fn cache_directory(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<PathBuf> {
    if let Some(dir) = cli.cache_dir.clone() {
        return Some(dir);
    }
    if let Some(cfg) = config {
        if let Some(p) = cfg.slopguard.cache.path.clone() {
            return Some(p);
        }
    }
    if let Some(found) = discover_cache_dir(Path::new(".")) {
        return Some(found);
    }
    Some(Path::new(DEFAULT_CACHE_DIR).to_path_buf())
}
