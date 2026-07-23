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
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))?;
        if let Some(fail_on) = cfg.codehound.fail_on.as_deref() {
            parse_fail_on(fail_on).map_err(Error::Config)?;
        }
        Ok(cfg)
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
        if let Some(fail_on) = self.codehound.fail_on.as_deref()
            && !cli_set_fail_policy
        {
            // Unknown values fall through to MediumAsErrors at load time via
            // parse_fail_on; prefer the Result form when validating configs.
            if let Some(policy) = try_fail_on_to_policy(fail_on) {
                ctx.fail_policy = policy;
            }
        }
        if let Some(enabled) = self.codehound.taint.enabled {
            ctx.taint_enabled = enabled;
        }
        if let Some(show_paths) = self.codehound.taint.show_paths {
            ctx.taint_show_paths = show_paths;
        }
        if let Some(enabled) = self.codehound.typed.enabled {
            ctx.typed_enabled = enabled;
        }
        ctx.bad_practices_enabled = self.codehound.bad_practices.enabled;
        ctx.bad_practice_severity = self.codehound.bad_practices.severity;
        ctx.severity_overrides
            .extend(self.codehound.bad_practices.severity_overrides);
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

/// Map a known `fail_on` string to a policy. Returns `None` for unknown values.
pub(crate) fn try_fail_on_to_policy(s: &str) -> Option<FailPolicy> {
    if s.eq_ignore_ascii_case("none") || s.eq_ignore_ascii_case("never") {
        Some(FailPolicy::NoFail)
    } else if s.eq_ignore_ascii_case("high") || s.eq_ignore_ascii_case("strict") {
        Some(FailPolicy::Strict)
    } else if s.eq_ignore_ascii_case("medium")
        || s.eq_ignore_ascii_case("warnings")
        || s.eq_ignore_ascii_case("default")
    {
        Some(FailPolicy::MediumAsErrors)
    } else {
        None
    }
}

/// Parse `fail_on`, rejecting unknown values (no silent fallback).
pub(crate) fn parse_fail_on(s: &str) -> Result<FailPolicy, String> {
    try_fail_on_to_policy(s).ok_or_else(|| {
        format!(
            "unknown fail_on value {s:?}; expected one of: none, never, medium, warnings, high, strict"
        )
    })
}

/// Legacy helper: map known values; unknown → MediumAsErrors.
/// Prefer [`parse_fail_on`] for new call sites that should reject typos.
#[allow(dead_code)]
pub(crate) fn fail_on_to_policy(s: &str) -> FailPolicy {
    try_fail_on_to_policy(s).unwrap_or(FailPolicy::MediumAsErrors)
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
