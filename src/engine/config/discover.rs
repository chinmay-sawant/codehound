//! Config-file discovery and `fail_on` policy mapping.

use std::path::Path;

use crate::Error;
use crate::core::FailPolicy;
use crate::engine::DEFAULT_CACHE_DIR;

use super::types::SlopguardConfig;

fn walk_up<F: Fn(&Path, &Path) -> bool>(
    start: &Path,
    stop_at_git: bool,
    predicate: F,
) -> Option<std::path::PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        if predicate(&current, start) {
            return Some(current.clone());
        }
        if stop_at_git && current.join(".git").is_dir() {
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Walk from `start` upward looking for the closest `.slopguard-cache/`
/// directory. Returns `None` if none is found in the chain. Used when
/// the user did not set `cache.path` in `slopguard.toml` and did not
/// pass `--cache-dir`.
pub fn discover_cache_dir(start: &Path) -> Option<std::path::PathBuf> {
    walk_up(start, true, |current, _| {
        current.join(DEFAULT_CACHE_DIR).is_dir()
    })
    .map(|dir| dir.join(DEFAULT_CACHE_DIR))
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
    walk_up(start, false, |current, _| {
        current.join("slopguard.toml").is_file()
    })
    .map(|dir| dir.join("slopguard.toml"))
}

/// Load `slopguard.toml` from the current directory when present.
///
/// # Errors
///
/// Propagates [`SlopguardConfig::load`] failures when `slopguard.toml` exists but
/// cannot be read or parsed.
#[must_use = "config load failures must be handled"]
pub fn load_discovered_config() -> Result<Option<SlopguardConfig>, Error> {
    let path = Path::new("slopguard.toml");
    if path.is_file() {
        Ok(Some(SlopguardConfig::load(path)?))
    } else {
        Ok(None)
    }
}
