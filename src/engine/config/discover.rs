//! Config-file discovery and `fail_on` policy mapping.

use std::path::Path;

use crate::Error;
use crate::core::{FailPolicy, ScanContext};
use crate::engine::DEFAULT_CACHE_DIR;
use crate::engine::path_walk::{WalkUpAction, walk_up_dirs};

use super::types::CodehoundConfig;

impl CodehoundConfig {
    /// Load and parse a `codehound.toml` file from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read and [`Error::Config`]
    /// when the TOML is invalid or contains unknown fields (serde `deny_unknown_fields`).
    #[must_use = "config load failures must be handled"]
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::from)?;
        toml::from_str(&text).map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))
    }

    /// Merge this config into a `ScanContext`. CLI-set fields take precedence:
    /// `skip` and `only` are merged additively, but
    /// `fail_policy` is only applied when the CLI did not pass an explicit
    /// one (signaled by `cli_set_fail_policy`).
    pub fn merge_into(self, mut ctx: ScanContext, cli_set_fail_policy: bool) -> ScanContext {
        if !self.codehound.skip.is_empty() {
            ctx.skip.extend(self.codehound.skip);
        }
        if !self.codehound.only.is_empty() {
            let mut only = ctx.only.take().unwrap_or_default();
            only.extend(self.codehound.only);
            ctx.only = Some(only);
        }
        if let Some(fail_on) = self.codehound.fail_on.as_deref() {
            if !cli_set_fail_policy {
                ctx.fail_policy = fail_on_to_policy(fail_on);
            }
        }
        if let Some(enabled) = self.codehound.taint.enabled {
            ctx.taint_enabled = enabled;
        }
        if let Some(show_paths) = self.codehound.taint.show_paths {
            ctx.taint_show_paths = show_paths;
        }
        ctx.bad_practices_enabled = self.codehound.bad_practices.enabled;
        ctx.bad_practice_severity = self.codehound.bad_practices.severity;
        ctx
    }
}

/// Walk from `start` upward looking for the closest `.codehound-cache/`
/// directory. Returns `None` if none is found in the chain. Used when
/// the user did not set `cache.path` in `codehound.toml` and did not
/// pass `--cache-dir`.
pub fn discover_cache_dir(start: &Path) -> Option<std::path::PathBuf> {
    walk_up_dirs(start, |current| {
        if current.join(".git").is_dir() {
            WalkUpAction::Stop
        } else if current.join(DEFAULT_CACHE_DIR).is_dir() {
            WalkUpAction::Found(current.join(DEFAULT_CACHE_DIR))
        } else {
            WalkUpAction::Continue
        }
    })
}

pub(crate) fn fail_on_to_policy(s: &str) -> FailPolicy {
    if s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("never") {
        FailPolicy::NoFail
    } else if s.eq_ignore_ascii_case("high") || s.eq_ignore_ascii_case("strict") {
        FailPolicy::Strict
    } else {
        FailPolicy::MediumAsErrors
    }
}

/// Walk from `start` upward looking for the closest `codehound.toml`.
pub fn discover_config(start: &Path) -> Option<std::path::PathBuf> {
    walk_up_dirs(start, |current| {
        if current.join("codehound.toml").is_file() {
            WalkUpAction::Found(current.join("codehound.toml"))
        } else {
            WalkUpAction::Continue
        }
    })
}
