//! Config-file discovery and `fail_on` policy mapping.

use std::path::Path;

use crate::core::FailPolicy;
use crate::engine::DEFAULT_CACHE_DIR;

use super::types::SlopguardConfig;

/// Walk from `start` upward looking for the closest `.slopguard-cache/`
/// directory. Returns `None` if none is found in the chain. Used when
/// the user did not set `cache.path` in `slopguard.toml` and did not
/// pass `--cache-dir`.
pub fn discover_cache_dir(start: &Path) -> Option<std::path::PathBuf> {
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
pub fn load_discovered_config() -> anyhow::Result<Option<SlopguardConfig>> {
    let path = Path::new("slopguard.toml");
    if path.is_file() {
        Ok(Some(SlopguardConfig::load(path)?))
    } else {
        Ok(None)
    }
}
